"""端到端测试：FastAPI + 内存存储 + 受控目录。

每个用例使用独立临时目录作为受控根，互不污染。
"""
from __future__ import annotations

import io
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app import main as main_mod
    from app.service import ArchiveService
    from app.storage.archive import MemoryStore
    from app.storage.filestore import FileStore

    archive_root = tmp_path / "archive"
    file_store = FileStore(archive_root)
    store = MemoryStore(file_store)
    service = ArchiveService(store, file_store, auto_rebuild=False)

    main_mod.app.dependency_overrides[main_mod.get_filestore] = lambda: file_store
    main_mod.app.dependency_overrides[main_mod.get_store] = lambda: store
    main_mod.app.dependency_overrides[main_mod.get_service] = lambda: service
    monkeypatch.setenv("MAIL_ARCHIVE_HOME", str(archive_root))
    with TestClient(main_mod.app) as c:
        c.file_store = file_store  # type: ignore[attr-defined]
        c.store = store  # type: ignore[attr-defined]
        c.root = archive_root  # type: ignore[attr-defined]
        yield c
    main_mod.app.dependency_overrides.clear()


def _upload(client: TestClient, data: bytes, filename: str = "mail.eml"):
    return client.post(
        "/api/v1/emails",
        files={"eml": (filename, io.BytesIO(data), "message/rfc822")},
    )


def _read_sample(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


# ---------------------------------------------------------------------------
# 摄取：多编码、多层 MIME、内嵌资源、危险名
# ---------------------------------------------------------------------------

def test_multi_encoding_multipart_structure(client):
    r = _upload(client, _read_sample("01_multi_encoding.eml"))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "ingested"
    assert body["message_id"]
    assert len(body["attachments"]) == 2

    detail = client.get(f"/api/v1/emails/{body['email_id']}").json()
    assert detail["subject"] == "会议测试multipart: 多部分测试"
    assert detail["from"][0]["name"] == "张三"
    assert detail["from"][0]["address"] == "alice@example.cn"
    assert detail["to"][0]["name"] == "Jörg"
    assert detail["to"][1]["name"] == "小王"

    # GB18030 纯文本正文正确解码
    assert "GB18030" in detail["body_text"]

    # MIME 树：outer mixed -> mixed -> [alternative(plain,html), inline, attachment]
    tree = detail["part_tree"]
    assert tree["is_multipart"] is True
    outer_mixed = tree["children"][0]
    assert len(outer_mixed["children"]) == 3
    alt = outer_mixed["children"][0]
    assert alt["content_type"] == "multipart/alternative"
    ctypes = sorted((c["content_type"], c["role"]) for c in alt["children"])
    assert ("text/html", "body") in ctypes
    assert ("text/plain", "body") in ctypes

    # HTML 安全
    h = detail["body_html_sanitized"]
    assert "<script" not in h.lower()
    assert "onclick" not in h.lower()
    assert "evil.example/tracker" not in h
    assert "javascript:alert" not in h
    assert "cid:logo-cid@example.cn" in h
    assert "https://example.cn/safe" in h
    # 完全转义版本存在
    assert "&lt;html&gt;" in detail["body_html_escaped"]

    # 附件分类：inline 带 CID，attachment 为 PDF
    atts = {a["kind"]: a for a in detail["attachments"]}
    assert "inline" in atts and "attachment" in atts
    assert atts["inline"]["content_id"] == "logo-cid@example.cn"
    assert atts["inline"]["part_path"] == "1.2"
    return body, detail


def test_attachment_path_traversal_neutralized(client):
    body, detail = test_multi_encoding_multipart_structure(client)
    pdf = next(a for a in detail["attachments"] if a["kind"] == "attachment")
    # 优先采用安全的 RFC2231 中文名，路径穿越只存在于 ASCII fallback（已弃用）
    assert pdf["safe_filename"] == "报告.. (1).pdf"
    assert "/" not in pdf["safe_filename"] and "\\" not in pdf["safe_filename"]
    assert pdf["safe_filename"].endswith(".pdf")
    assert pdf["relative_path"].count("/") == 3  # aa/bb/<sha>.pdf，完全内容寻址
    # 存储路径完全由 sha 决定，且全部落在受控根
    root = Path(os.environ["MAIL_ARCHIVE_HOME"])
    target = (root / pdf["relative_path"]).resolve()
    assert root.resolve() in target.parents
    # 相对路径无任何 .. 段
    assert ".." not in Path(pdf["relative_path"]).parts

    # 下载附件成功
    r = client.get(f"/api/v1/attachments/{pdf['id']}/raw")
    assert r.status_code == 200
    assert r.content.startswith(b"%PDF")
    cd = r.headers["content-disposition"]
    assert "attachment" in cd
    assert "/" not in cd.split("filename=")[-1] or ".." not in cd


def test_attachment_dedup_same_content(client):
    _upload(client, _read_sample("01_multi_encoding.eml"))
    # 同内容再传（整封 SHA 相同，走内容去重）
    r2 = _upload(client, _read_sample("01_multi_encoding.eml"))
    assert r2.json()["status"] == "duplicate-content"


# ---------------------------------------------------------------------------
# 循环引用
# ---------------------------------------------------------------------------

def test_circular_references_terminate_and_mark(client):
    r = _upload(client, _read_sample("02_circular_references.eml"))
    assert r.status_code == 201
    email_id = r.json()["email_id"]
    detail = client.get(f"/api/v1/emails/{email_id}").json()
    refs = {e["target_message_id"] for e in detail["references"]}
    assert "cycle-a@example.com" in refs  # 自引用边完整保留
    assert "cycle-c@example.com" in refs

    # 自引用单环
    rb = client.post("/api/v1/threads/rebuild").json()
    assert rb["cycle_count"] >= 1
    flat = [m for cyc in rb["cycles"] for m in cyc]
    assert "cycle-a@example.com" in flat

    # rebuild 后详情中可见会话号
    detail2 = client.get(f"/api/v1/emails/{email_id}").json()
    assert detail2["thread_id"]


# ---------------------------------------------------------------------------
# 损坏边界 / 坏编码
# ---------------------------------------------------------------------------

def test_broken_boundary_records_structural_defect(client):
    r = _upload(client, _read_sample("03_broken_boundary.eml"))
    assert r.status_code == 201
    body = r.json()
    assert body["has_errors"] is True
    types = {d["defect_type"] for d in body["defects"]}
    assert "CloseBoundaryNotFoundDefect" in types
    # 缺陷定位到部件路径
    assert all("part_path" in d for d in body["defects"])


def test_corrupted_encoding_reports_locatable_defects(client):
    r = _upload(client, _read_sample("04_corrupted_encoding.eml"))
    assert r.status_code == 201
    detail = client.get(f"/api/v1/emails/{r.json()['email_id']}").json()
    # 未知字符集回退，正文仍可读
    assert "x-unknown-cs-1999" in detail["body_text"]
    dmap = {(d["part_path"], d["defect_type"]) for d in detail["defects"]}
    assert ("2", "InvalidBase64CharactersDefect") in dmap
    assert ("2", "InvalidBase64PaddingDefect") in dmap
    # 坏 base64 附件仍然保存，不丢数据
    att = detail["attachments"][0]
    rr = client.get(f"/api/v1/attachments/{att['id']}/raw")
    assert rr.status_code == 200


# ---------------------------------------------------------------------------
# Message-ID 缺失 / 重复 / 主题弱候选
# ---------------------------------------------------------------------------

def test_missing_message_id_retained_not_merged(client):
    r = _upload(client, _read_sample("05_missing_message_id.eml"))
    assert r.status_code == 201
    assert r.json()["message_id"] is None
    conflicts = client.get("/api/v1/conflicts").json()
    assert r.json()["email_id"] in conflicts["missing_message_ids"]


def test_duplicate_message_id_conflict_retained(client):
    a = _upload(client, _read_sample("06_duplicate_message_id_a.eml")).json()
    b = _upload(client, _read_sample("06_duplicate_message_id_b.eml")).json()
    assert b["status"] == "conflict-retained"
    assert b["duplicate_of"] == a["email_id"]
    # 两条记录都在
    conflicts = client.get("/api/v1/conflicts").json()
    group = next(g for g in conflicts["duplicate_message_ids"]
                 if g["message_id"] == "quarterly-report-2023q3@example.com")
    assert len(group["emails"]) == 2
    assert group["resolution"] == "retained-conflict"
    # 都能独立取到
    assert client.get(f"/api/v1/emails/{a['email_id']}").status_code == 200
    assert client.get(f"/api/v1/emails/{b['email_id']}").status_code == 200


def test_same_subject_is_only_weak_candidate(client):
    _upload(client, _read_sample("05_missing_message_id.eml"))
    r8 = _upload(client, _read_sample("08_same_subject_weak_candidate.eml")).json()
    rb = client.post("/api/v1/threads/rebuild").json()
    # 弱候选出现
    keys = {c["subject_key"] for c in rb["weak_subject_candidates"]}
    assert any("扫描的文档" in k for k in keys)
    # 但 08 未被并入任何会话（它没有 in-reply-to/references）
    d8 = client.get(f"/api/v1/emails/{r8['email_id']}").json()
    assert d8["thread_id"] is None


# ---------------------------------------------------------------------------
# 致命损坏：隔离、失败可定位
# ---------------------------------------------------------------------------

def test_fatal_parse_failure_quarantined_and_locatable(client):
    r = _upload(client, _read_sample("07_not_an_eml.bin"), filename="07.bin")
    assert r.status_code == 422
    payload = r.json()["detail"]
    assert payload["status"] == "failed"
    fid = payload["failure_id"]
    assert payload["quarantine_path"]
    # 失败列表与定位接口
    listed = client.get("/api/v1/failures").json()
    assert any(f["id"] == fid for f in listed)
    one = client.get(f"/api/v1/failures/{fid}").json()
    assert one["stage"] in {"headers", "rfc822", "input"}
    assert one["raw_sha256"] == payload["raw_sha256"]

    # 隔离文件确实在受控 quarantine 下且与原始输入字节一致
    root = Path(os.environ["MAIL_ARCHIVE_HOME"])
    q = (root / one["quarantine_path"]).resolve()
    assert (root / "quarantine").resolve() in q.parents
    assert q.read_bytes() == _read_sample("07_not_an_eml.bin")
    assert client.get(f"/api/v1/failures/{fid}").status_code == 200


def test_empty_body_rejected(client):
    r = _upload(client, b"   \n  ")
    assert r.status_code == 422
    assert r.json()["detail"]["status"] == "failed"


# ---------------------------------------------------------------------------
# 检索、raw 下载、越界访问
# ---------------------------------------------------------------------------

def test_search_and_message_id_filter(client):
    _upload(client, _read_sample("01_multi_encoding.eml"))
    _upload(client, _read_sample("06_duplicate_message_id_a.eml"))
    # 全文检索中文
    r = client.get("/api/v1/emails", params={"q": "GB18030"})
    assert r.status_code == 200
    assert r.json()["total"] == 1
    # Message-ID 精确过滤
    r2 = client.get(
        "/api/v1/emails",
        params={"message_id": "<quarterly-report-2023q3@example.com>"},
    )
    assert r2.json()["total"] == 1


def test_raw_download_is_attachment_and_linked(client):
    b = _upload(client, _read_sample("01_multi_encoding.eml")).json()
    r = client.get(f"/api/v1/emails/{b['email_id']}/raw")
    assert r.status_code == 200
    assert r.headers["content-type"] == "message/rfc822"
    assert "attachment" in r.headers["content-disposition"]
    assert r.content == _read_sample("01_multi_encoding.eml")


def test_attachment_404_and_traversal(client):
    assert client.get("/api/v1/attachments/nonexistent/raw").status_code == 404
    assert client.get("/api/v1/emails/nonexistent").status_code == 404


# ---------------------------------------------------------------------------
# 日志不泄漏附件内容
# ---------------------------------------------------------------------------

def test_logs_never_contain_attachment_payload(client, caplog, tmp_path):
    import logging

    marker = b"SECRET-MARKER-SHOULD-NEVER-APPEAR-IN-LOGS"
    # 构造一个带唯一标记的 EML 附件
    from email.message import EmailMessage

    m = EmailMessage()
    m["From"] = "a@x.com"
    m["To"] = "b@x.com"
    m["Subject"] = "log leak test"
    m["Message-ID"] = "<logleak@x.com>"
    m.set_content("body")
    m.add_attachment(marker + b"-payload-data", maintype="application",
                     subtype="octet-stream", filename="secret.bin")
    data = bytes(m)

    with caplog.at_level(logging.DEBUG):
        r = _upload(client, data)
    assert r.status_code == 201
    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert marker.decode() not in joined
    assert "SECRET-MARKER" not in joined


def test_redactor_replaces_long_blob():
    from app.logging_config import redact_text

    blob = "A" * 500
    out = redact_text(f"data:{blob}:end")
    assert "<redacted:" in out
    assert "AAAA" not in out
