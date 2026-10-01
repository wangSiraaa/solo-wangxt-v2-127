"""PostgreSQL 后端集成测试。

默认尝试通过 ``embedded-postgres`` 自动拉起本地 PG；也可用环境变量
``MAIL_TEST_DSN`` 指定已运行的实例。无可用 PG 时整个文件 skip。
"""
from __future__ import annotations

import pathlib
from contextlib import contextmanager
from pathlib import Path

import pytest

from app.service import ArchiveService, IngestError
from app.storage.filestore import FileStore
from app.storage.postgres import PostgresStore

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
PGDATA = pathlib.Path("/tmp/pgdata-mail-test")


@contextmanager
def _postgres_dsn():
    import os

    dsn = os.environ.get("MAIL_TEST_DSN")
    if dsn:
        yield dsn
        return
    try:
        from embedded_postgres import PostgresServer
    except ImportError:
        pytest.skip("embedded-postgres 未安装")
    pg = PostgresServer(PGDATA, cleanup_mode=None)
    try:
        pg.ensure_pgdata_inited()
        pg.ensure_postgres_running()
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"嵌入式 PostgreSQL 无法启动: {exc}")
    base = pg.get_uri()
    db = "mailarchive_it"
    import psycopg

    with psycopg.connect(base, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {db}")
        conn.execute(f"CREATE DATABASE {db}")
    yield base.replace("/postgres?", f"/{db}?")


@pytest.fixture(scope="module")
def pg_env(tmp_path_factory):
    with _postgres_dsn() as dsn:
        root = tmp_path_factory.mktemp("pg-archive")
        store = PostgresStore(dsn)
        fs = FileStore(root)
        svc = ArchiveService(store, fs, auto_rebuild=False)
        yield {"store": store, "fs": fs, "svc": svc, "root": root}
        store.close()


def _ingest(pg_env, name):
    return pg_env["svc"].ingest((SAMPLES / name).read_bytes())


def test_pg_ingest_multi_encoding(pg_env):
    r = _ingest(pg_env, "01_multi_encoding.eml")
    assert r["status"] == "ingested"
    detail = pg_env["store"].get_email_full(r["email_id"])
    assert detail["subject"] == "会议测试multipart: 多部分测试"
    assert detail["from"][0]["name"] == "张三"
    assert len(detail["attachments"]) == 2
    # 关系边落库
    kinds = {(e["kind"], e["target_message_id"]) for e in detail["references"]}
    assert ("in-reply-to", "parent-1@example.cn") in kinds
    assert ("references", "grand-0@example.cn") in kinds
    # 附件采用安全 RFC2231 名；路径完全内容寻址
    pdf = next(a for a in detail["attachments"] if a["kind"] == "attachment")
    assert pdf["safe_filename"] == "报告.. (1).pdf"
    assert "/" not in pdf["safe_filename"] and "\\" not in pdf["safe_filename"]
    assert pdf["relative_path"].count("/") == 3
    path, _ = pg_env["fs"].open_blob(pdf["relative_path"])
    assert pg_env["root"].resolve() in path.resolve().parents
    assert path.read_bytes().startswith(b"%PDF")


def test_pg_duplicate_message_id_retains_conflict(pg_env):
    a = _ingest(pg_env, "06_duplicate_message_id_a.eml")
    b = _ingest(pg_env, "06_duplicate_message_id_b.eml")
    assert b["status"] == "conflict-retained"
    assert b["duplicate_of"] == a["email_id"]
    conflicts = pg_env["store"].list_conflicts()
    group = next(
        g for g in conflicts["duplicate_message_ids"]
        if g["message_id"] == "quarterly-report-2023q3@example.com"
    )
    assert len(group["emails"]) == 2
    assert group["resolution"] == "retained-conflict"
    assert pg_env["store"].get_email(a["email_id"]) is not None
    assert pg_env["store"].get_email(b["email_id"]) is not None


def test_pg_circular_and_thread_rebuild(pg_env):
    _ingest(pg_env, "02_circular_references.eml")
    rb = pg_env["store"].rebuild()
    flat = {m for cyc in rb["cycles"] for m in cyc}
    assert "cycle-a@example.com" in flat
    assert rb["self_references"]
    # 同主题弱候选（05/08 也在库中，见后续用例；此处只校验循环邮件自身有 thread）
    detail = pg_env["store"].list_emails(None, "cycle-a@example.com", 10, 0)[0][0]
    assert detail["thread_id"]


def test_pg_same_subject_not_merged(pg_env):
    r5 = _ingest(pg_env, "05_missing_message_id.eml")
    r8 = _ingest(pg_env, "08_same_subject_weak_candidate.eml")
    rb = pg_env["store"].rebuild()
    assert rb["weak_candidate_count"] >= 1
    assert any("扫描的文档" in c["subject_key"] for c in rb["weak_subject_candidates"])
    d8 = pg_env["store"].get_email(r8["email_id"])
    assert d8["thread_id"] is None
    conflicts = pg_env["store"].list_conflicts()
    assert r5["email_id"] in conflicts["missing_message_ids"]


def test_pg_failure_quarantined_and_locatable(pg_env):
    with pytest.raises(IngestError) as exc:
        pg_env["svc"].ingest((SAMPLES / "07_not_an_eml.bin").read_bytes())
    fid = exc.value.payload["failure_id"]
    row = pg_env["store"].get_failure(fid)
    assert row is not None and row["stage"] in {"headers", "rfc822", "input"}
    qpath = (pg_env["root"] / row["quarantine_path"]).resolve()
    assert qpath.read_bytes() == (SAMPLES / "07_not_an_eml.bin").read_bytes()
    assert any(f["id"] == fid for f in pg_env["store"].list_failures(50))


def test_pg_broken_and_corrupted(pg_env):
    r3 = _ingest(pg_env, "03_broken_boundary.eml")
    assert any(d["defect_type"] == "CloseBoundaryNotFoundDefect" for d in r3["defects"])
    r4 = _ingest(pg_env, "04_corrupted_encoding.eml")
    dmap = {(d["part_path"], d["defect_type"]) for d in r4["defects"]}
    assert ("2", "InvalidBase64CharactersDefect") in dmap


def test_pg_fts_search(pg_env):
    # 重新重建（触发所有 FTS 索引更新；FTS 是表达式索引无需触发器）
    items, total = pg_env["store"].list_emails("GB18030", None, 10, 0)
    assert total >= 1
    items, total = pg_env["store"].list_emails("不存在的检索词xyz", None, 10, 0)
    assert total == 0


def test_pg_content_dedup(pg_env):
    r1 = _ingest(pg_env, "01_multi_encoding.eml")
    assert r1["status"] == "duplicate-content"
