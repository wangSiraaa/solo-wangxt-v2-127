"""PostgreSQL 存储后端。

与 MemoryStore 实现同一套 ArchiveStore 语义：
* Message-ID 无唯一约束，重复保留为多条 + duplicate_of 指针；
* References/In-Reply-To 全量落 email_edges，含悬挂/循环；
* 会话重算结果整体替换 threads/thread_cycles/dangling_refs/subject_candidates；
* 字节内容不进库，库内只有相对路径与 sha256。
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from psycopg.rows import dict_row
from psycopg.sql import SQL
from psycopg_pool import ConnectionPool

from ..logging_config import get_logger
from ..parsing import rebuild_threads, weak_subject_candidates
from ..parsing.models import ParsedMessage
from .archive import ArchiveStore, AttachmentRow, FailureRow, parsed_to_record_fields
from .filestore import StoredBlob

log = get_logger("postgres")

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")
_PARTICIPANT_FIELDS = ("from", "to", "cc", "bcc", "sender", "reply-to")
_FIELD_COLUMN = {
    "from": "from_addr",
    "to": "to_addr",
    "cc": "cc_addr",
    "bcc": "bcc_addr",
    "sender": "sender_addr",
    "reply-to": "reply_to",
}


def _jsonable(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


class PostgresStore(ArchiveStore):
    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 5) -> None:
        self.pool = ConnectionPool(dsn, min_size=min_size, max_size=max_size, open=False, kwargs={"row_factory": dict_row})
        self.pool.open()
        self.init_schema()

    def init_schema(self) -> None:
        ddl = _SCHEMA_PATH.read_text(encoding="utf-8")
        with self.pool.connection() as conn:
            conn.execute(ddl)
        log.info("schema ready")

    def close(self) -> None:
        self.pool.close()

    # ------------------------------------------------------------------
    def find_by_sha(self, sha256: str) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT * FROM emails WHERE raw_sha256 = %s", (sha256,)
            ).fetchone()
        return self._hydrate(row) if row else None

    def find_duplicate_message_ids(self, message_id: str | None, sha256: str) -> list[dict[str, Any]]:
        if not message_id:
            return []
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT id, raw_sha256, subject FROM emails WHERE message_id = %s AND raw_sha256 <> %s",
                (message_id, sha256),
            ).fetchall()
        return [{"id": str(r["id"]), "raw_sha256": r["raw_sha256"], "subject": r["subject"]} for r in rows]

    def save_email(
        self,
        parsed: ParsedMessage,
        raw_blob: StoredBlob,
        attachments: list[AttachmentRow],
        duplicate_of: str | None,
        now_iso: str,
    ) -> dict[str, Any]:
        email_id = uuid.uuid4()
        fields = parsed_to_record_fields(parsed)
        date_value = parsed.date_iso
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute(
                    SQL("""
                        INSERT INTO emails (
                            id, raw_sha256, raw_size, raw_path, raw_reused,
                            message_id, message_id_raw, date_iso, subject, subject_raw,
                            from_addr, to_addr, cc_addr, bcc_addr, sender_addr, reply_to,
                            body_text, body_html_sanitized, body_html_escaped,
                            body_part_path_text, body_part_path_html,
                            part_tree, headers, header_summary, defects, has_errors,
                            duplicate_of, created_at
                        ) VALUES (
                            %s,%s,%s,%s,%s, %s,%s,%s,%s,%s,
                            %s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb,
                            %s,%s,%s, %s,%s,
                            %s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb,%s,
                            %s,%s
                        )
                    """),
                    (
                        email_id, parsed.raw_sha256, parsed.raw_size, raw_blob.path, raw_blob.reused,
                        parsed.message_id, parsed.message_id_raw, date_value, parsed.subject_decoded, parsed.subject_raw,
                        _jsonable(fields["from_addr"]), _jsonable(fields["to_addr"]),
                        _jsonable(fields["cc_addr"]), _jsonable(fields["bcc_addr"]),
                        _jsonable(fields["sender_addr"]), _jsonable(fields["reply_to"]),
                        parsed.body_text, parsed.body_html_sanitized, parsed.body_html_escaped,
                        parsed.body_part_path_text, parsed.body_part_path_html,
                        _jsonable(fields["part_tree"]), _jsonable(fields["headers"]),
                        _jsonable(fields["header_summary"]), _jsonable(fields["defects"]),
                        parsed.has_errors,
                        uuid.UUID(duplicate_of) if duplicate_of else None,
                        now_iso,
                    ),
                )
                self._insert_participants(conn, email_id, fields)
                self._insert_edges(conn, email_id, fields["references"])
                for att in attachments:
                    conn.execute(
                        """INSERT INTO attachments
                           (id, email_id, sha256, relative_path, original_filename, safe_filename,
                            content_type, content_id, content_location, disposition, kind, size, part_path)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            uuid.UUID(att.id), email_id, att.sha256, att.relative_path,
                            att.original_filename, att.safe_filename, att.content_type,
                            att.content_id, att.content_location, att.disposition,
                            att.kind, att.size, att.part_path,
                        ),
                    )
        row = self.find_by_sha(parsed.raw_sha256)
        assert row is not None
        return row

    def add_attachments(self, email_id: str, attachments: list[AttachmentRow]) -> None:
        with self.pool.connection() as conn:
            for att in attachments:
                conn.execute(
                    """INSERT INTO attachments
                       (id, email_id, sha256, relative_path, original_filename, safe_filename,
                        content_type, content_id, content_location, disposition, kind, size, part_path)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        uuid.UUID(att.id), uuid.UUID(email_id), att.sha256, att.relative_path,
                        att.original_filename, att.safe_filename, att.content_type,
                        att.content_id, att.content_location, att.disposition,
                        att.kind, att.size, att.part_path,
                    ),
                )

    def _insert_participants(self, conn, email_id: uuid.UUID, fields: dict[str, Any]) -> None:
        for field_name in _PARTICIPANT_FIELDS:
            for ordinal, person in enumerate(fields[_FIELD_COLUMN[field_name]]):
                addr = (person.get("address") or "").strip().lower()
                name = person.get("name") or None
                if not addr and not name:
                    continue
                pid = None
                if addr:
                    cur = conn.execute(
                        """INSERT INTO participants (email, name) VALUES (%s, %s)
                           ON CONFLICT (email) DO UPDATE SET name = COALESCE(participants.name, EXCLUDED.name)
                           RETURNING id""",
                        (addr, name),
                    )
                    pid = cur.fetchone()["id"]
                else:
                    cur = conn.execute(
                        "INSERT INTO participants (email, name) VALUES (NULL, %s) RETURNING id",
                        (name,),
                    )
                    pid = cur.fetchone()["id"]
                conn.execute(
                    """INSERT INTO email_participants (email_id, participant_id, field_name, ordinal)
                       VALUES (%s,%s,%s,%s)
                       ON CONFLICT DO NOTHING""",
                    (email_id, pid, field_name, ordinal),
                )

    def _insert_edges(self, conn, email_id: uuid.UUID, edges: list[dict[str, Any]]) -> None:
        # 回填 target_email_id（可能尚不存在 -> NULL，记为悬挂）
        for edge in edges:
            target = edge["target_message_id"]
            row = conn.execute("SELECT id FROM emails WHERE message_id = %s ORDER BY created_at LIMIT 1", (target,)).fetchone()
            conn.execute(
                """INSERT INTO email_edges (email_id, kind, target_message_id, ordinal, raw, target_email_id)
                   VALUES (%s,%s,%s,%s,%s,%s)""",
                (email_id, edge["kind"], target, edge["ordinal"], edge.get("raw"), row["id"] if row else None),
            )

    def save_failure(self, failure: FailureRow) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                """INSERT INTO parse_failures (id, raw_sha256, raw_size, stage, error_type, message, quarantine_path, created_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    uuid.UUID(failure.id), failure.raw_sha256, failure.raw_size,
                    failure.stage, failure.error_type, failure.message,
                    failure.quarantine_path, failure.created_at,
                ),
            )

    # ------------------------------------------------------------------
    def _hydrate(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        out["id"] = str(row["id"])
        if row.get("duplicate_of"):
            out["duplicate_of"] = str(row["duplicate_of"])
        for key in ("from_addr", "to_addr", "cc_addr", "bcc_addr", "sender_addr",
                    "reply_to", "part_tree", "headers", "header_summary", "defects"):
            value = row.get(key)
            out[key] = value if value is not None else ([] if key != "part_tree" else {})
        out["references"] = []  # 详情查询时按需填充
        out["from"] = out.get("from_addr", [])
        out.setdefault("to", out.get("to_addr", []))
        out.setdefault("cc", out.get("cc_addr", []))
        out.setdefault("bcc", out.get("bcc_addr", []))
        out.setdefault("sender", out.get("sender_addr", []))
        if isinstance(row.get("date_iso"), datetime):
            out["date_iso"] = row["date_iso"].isoformat()
        if isinstance(row.get("created_at"), datetime):
            out["created_at"] = row["created_at"].isoformat()
        return out

    def get_email(self, email_id: str) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT * FROM emails WHERE id = %s", (uuid.UUID(email_id),)).fetchone()
        return self._summary(self._hydrate(row)) if row else None

    def get_email_full(self, email_id: str) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT * FROM emails WHERE id = %s", (uuid.UUID(email_id),)).fetchone()
            if not row:
                return None
            edges = conn.execute(
                "SELECT kind, target_message_id, ordinal, raw FROM email_edges WHERE email_id = %s ORDER BY kind, ordinal",
                (uuid.UUID(email_id),),
            ).fetchall()
            atts = conn.execute("SELECT * FROM attachments WHERE email_id = %s ORDER BY part_path", (uuid.UUID(email_id),)).fetchall()
        full = self._hydrate(row)
        full["references"] = [
            {"kind": e["kind"], "target_message_id": e["target_message_id"],
             "ordinal": e["ordinal"], "raw": e["raw"]} for e in edges
        ]
        full["attachments"] = [self._hydrate_attachment(a) for a in atts]
        return full

    def _hydrate_attachment(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        out["id"] = str(row["id"])
        out["email_id"] = str(row["email_id"])
        return out

    def _summary(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "message_id": row.get("message_id"),
            "message_id_raw": row.get("message_id_raw"),
            "date_iso": row.get("date_iso"),
            "subject": row.get("subject"),
            "from": row.get("from_addr", []),
            "to": row.get("to_addr", []),
            "raw_sha256": row["raw_sha256"],
            "raw_size": row["raw_size"],
            "raw_path": row["raw_path"],
            "has_errors": row["has_errors"],
            "defect_count": len(row.get("defects", [])),
            "duplicate_of": row.get("duplicate_of"),
            "thread_id": row.get("thread_id"),
            "created_at": row.get("created_at"),
        }

    def list_emails(
        self, q: str | None, message_id: str | None, limit: int, offset: int
    ) -> tuple[list[dict[str, Any]], int]:
        where = []
        params: list[Any] = []
        if message_id:
            where.append("message_id = %s")
            params.append(message_id.lower())
        if q:
            where.append("mail_fts_document(emails) @@ plainto_tsquery('simple', %s)")
            params.append(q)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.pool.connection() as conn:
            total = conn.execute(
                SQL("SELECT count(*) AS c FROM emails {tbl}").format(tbl=SQL(clause)), params
            ).fetchone()["c"]
            rows = conn.execute(
                SQL("SELECT * FROM emails {tbl} ORDER BY date_iso DESC NULLS LAST, created_at DESC LIMIT %s OFFSET %s").format(
                    tbl=SQL(clause)
                ),
                params + [limit, offset],
            ).fetchall()
        return [self._summary(self._hydrate(r)) for r in rows], total

    def get_attachment(self, attachment_id: str) -> AttachmentRow | None:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT * FROM attachments WHERE id = %s", (uuid.UUID(attachment_id),)).fetchone()
        if not row:
            return None
        return AttachmentRow(
            id=str(row["id"]), email_id=str(row["email_id"]), sha256=row["sha256"],
            relative_path=row["relative_path"], original_filename=row["original_filename"],
            safe_filename=row["safe_filename"], content_type=row["content_type"],
            content_id=row["content_id"], content_location=row["content_location"],
            disposition=row["disposition"], kind=row["kind"], size=row["size"],
            part_path=row["part_path"],
        )

    def list_attachments(self, email_id: str) -> list[AttachmentRow]:
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT * FROM attachments WHERE email_id = %s ORDER BY part_path", (uuid.UUID(email_id),)).fetchall()
        return [
            AttachmentRow(
                id=str(r["id"]), email_id=str(r["email_id"]), sha256=r["sha256"],
                relative_path=r["relative_path"], original_filename=r["original_filename"],
                safe_filename=r["safe_filename"], content_type=r["content_type"],
                content_id=r["content_id"], content_location=r["content_location"],
                disposition=r["disposition"], kind=r["kind"], size=r["size"],
                part_path=r["part_path"],
            ) for r in rows
        ]

    # ------------------------------------------------------------------
    def rebuild(self) -> dict[str, Any]:
        with self.pool.connection() as conn:
            email_rows = conn.execute("SELECT id, message_id, subject, date_iso FROM emails ORDER BY created_at").fetchall()
            edge_rows = conn.execute(
                "SELECT email_id, kind, target_message_id FROM email_edges"
            ).fetchall()

            id_to_db = {r["message_id"]: str(r["id"]) for r in email_rows if r["message_id"]}
            db_to_mid = {v: k for k, v in id_to_db.items()}
            edges: list[tuple[str | None, str]] = []
            for e in edge_rows:
                edges.append((db_to_mid.get(str(e["email_id"])), e["target_message_id"]))

            nodes = [r["message_id"] for r in email_rows if r["message_id"]]
            result = rebuild_threads(nodes, edges)
            weak = weak_subject_candidates([(str(r["id"]), r["subject"]) for r in email_rows])

            with conn.transaction():
                conn.execute("UPDATE emails SET thread_id = NULL")
                conn.execute("TRUNCATE threads, thread_cycles, dangling_refs, subject_candidates")
                groups: dict[str, list[str]] = {}
                for mid, tid in result.members.items():
                    groups.setdefault(tid, []).append(mid)
                cyclic_nodes = {m for cyc in result.cycles for m in cyc}
                for tid, members in groups.items():
                    cycle = any(mid in cyclic_nodes for mid in members)
                    conn.execute(
                        "INSERT INTO threads (thread_id, cycle, member_count) VALUES (%s,%s,%s)",
                        (tid, cycle, len(members)),
                    )
                    for mid in members:
                        db_id = id_to_db.get(mid)
                        if db_id:
                            conn.execute("UPDATE emails SET thread_id = %s WHERE id = %s", (tid, db_id))
                for cyc in result.cycles:
                    conn.execute("INSERT INTO thread_cycles (cycle_path) VALUES (%s::jsonb)", (_jsonable(cyc),))
                for d in result.dangling:
                    conn.execute("INSERT INTO dangling_refs (src, target, kind) VALUES (%s,%s,%s)",
                                 (d.get("src"), d["target"], d["kind"]))
                for cand in weak:
                    conn.execute("INSERT INTO subject_candidates (subject_key, email_ids) VALUES (%s,%s::jsonb)",
                                 (cand["subject_key"], _jsonable(cand["email_ids"])))

        return {
            "thread_count": len({t for t in result.members.values()}),
            "cycles": result.cycles,
            "cycle_count": len(result.cycles),
            "self_references": result.self_references,
            "dangling": result.dangling,
            "dangling_count": len(result.dangling),
            "weak_subject_candidates": weak,
            "weak_candidate_count": len(weak),
        }

    def get_thread(self, thread_id: str) -> dict[str, Any]:
        with self.pool.connection() as conn:
            thread = conn.execute("SELECT * FROM threads WHERE thread_id = %s", (thread_id,)).fetchone()
            if not thread:
                return {"thread_id": thread_id, "members": [], "found": False}
            members = conn.execute(
                """SELECT id, message_id, subject, date_iso FROM emails
                   WHERE thread_id = %s ORDER BY date_iso ASC NULLS LAST, created_at ASC""",
                (thread_id,),
            ).fetchall()
            cycles = conn.execute("SELECT cycle_path FROM thread_cycles").fetchall()
        return {
            "thread_id": thread_id,
            "cycle": thread["cycle"],
            "found": True,
            "members": [
                {"email_id": str(m["id"]), "message_id": m["message_id"],
                 "subject": m["subject"], "date_iso": m["date_iso"].isoformat() if m["date_iso"] else None}
                for m in members
            ],
            "cycles_in_store": [c["cycle_path"] for c in cycles],
        }

    def list_conflicts(self) -> dict[str, Any]:
        with self.pool.connection() as conn:
            dup_rows = conn.execute(
                """SELECT message_id, jsonb_agg(jsonb_build_object(
                       'email_id', id, 'raw_sha256', raw_sha256, 'subject', subject,
                       'created_at', created_at) ORDER BY created_at) AS emails
                   FROM emails WHERE message_id IS NOT NULL
                   GROUP BY message_id HAVING count(*) > 1"""
            ).fetchall()
            missing = conn.execute("SELECT id FROM emails WHERE message_id IS NULL").fetchall()
        return {
            "duplicate_message_ids": [
                {"message_id": r["message_id"],
                 "emails": [{**e, "email_id": str(e["email_id"]),
                             "created_at": e["created_at"].isoformat() if isinstance(e.get("created_at"), datetime) else e.get("created_at")}
                            for e in r["emails"]],
                 "resolution": "retained-conflict"}
                for r in dup_rows
            ],
            "missing_message_ids": [str(r["id"]) for r in missing],
        }

    def list_failures(self, limit: int) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM parse_failures ORDER BY created_at DESC LIMIT %s", (limit,)
            ).fetchall()
        return [self._hydrate_failure(r) for r in rows]

    def get_failure(self, failure_id: str) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT * FROM parse_failures WHERE id = %s", (uuid.UUID(failure_id),)).fetchone()
        return self._hydrate_failure(row) if row else None

    @staticmethod
    def _hydrate_failure(row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        out["id"] = str(row["id"])
        if isinstance(row.get("created_at"), datetime):
            out["created_at"] = row["created_at"].isoformat()
        return out
