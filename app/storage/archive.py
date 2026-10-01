"""档案存储抽象与内存实现。

服务层只依赖 ``ArchiveStore`` 接口；PostgreSQL 实现在 postgres.py。
内存实现保证离线/CI 环境下全部 API 可运行，且行为与 PG 版语义一致
（重复 Message-ID 不合并、引用边全保留、失败可定位）。
"""
from __future__ import annotations

import abc
import uuid
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from ..parsing import (
    ParsedMessage,
    rebuild_threads,
    weak_subject_candidates,
)
from ..storage.filestore import StoredBlob

if TYPE_CHECKING:
    from ..storage.filestore import FileStore


def _new_id() -> str:
    return str(uuid.uuid4())


@dataclass
class AttachmentRow:
    id: str
    email_id: str
    sha256: str
    relative_path: str
    original_filename: str | None
    safe_filename: str
    content_type: str
    content_id: str | None
    content_location: str | None
    disposition: str | None
    kind: str
    size: int
    part_path: str


@dataclass
class FailureRow:
    id: str
    raw_sha256: str
    raw_size: int
    stage: str
    error_type: str
    message: str
    quarantine_path: str | None
    created_at: str


class ArchiveStore(abc.ABC):
    @abc.abstractmethod
    def find_by_sha(self, sha256: str) -> dict[str, Any] | None: ...

    @abc.abstractmethod
    def find_duplicate_message_ids(self, message_id: str | None, sha256: str) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    def save_email(
        self,
        parsed: ParsedMessage,
        raw_blob: StoredBlob,
        attachments: list[AttachmentRow],
        duplicate_of: str | None,
        now_iso: str,
    ) -> dict[str, Any]: ...

    @abc.abstractmethod
    def add_attachments(self, email_id: str, attachments: list[AttachmentRow]) -> None: ...

    @abc.abstractmethod
    def save_failure(self, failure: FailureRow) -> None: ...

    @abc.abstractmethod
    def get_email(self, email_id: str) -> dict[str, Any] | None: ...

    @abc.abstractmethod
    def get_email_full(self, email_id: str) -> dict[str, Any] | None: ...

    @abc.abstractmethod
    def list_emails(
        self, q: str | None, message_id: str | None, limit: int, offset: int
    ) -> tuple[list[dict[str, Any]], int]: ...

    @abc.abstractmethod
    def get_attachment(self, attachment_id: str) -> AttachmentRow | None: ...

    @abc.abstractmethod
    def list_attachments(self, email_id: str) -> list[AttachmentRow]: ...

    @abc.abstractmethod
    def rebuild(self) -> dict[str, Any]: ...

    @abc.abstractmethod
    def get_thread(self, thread_id: str) -> dict[str, Any]: ...

    @abc.abstractmethod
    def list_conflicts(self) -> dict[str, Any]: ...

    @abc.abstractmethod
    def list_failures(self, limit: int) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    def get_failure(self, failure_id: str) -> dict[str, Any] | None: ...


# ---------------------------------------------------------------------------
# 序列化辅助
# ---------------------------------------------------------------------------

def _part_tree(part) -> dict[str, Any]:
    return {
        "part_path": part.part_path,
        "content_type": part.content_type,
        "disposition": part.disposition,
        "filename": part.filename,
        "content_id": part.content_id,
        "content_location": part.content_location,
        "charset": part.charset,
        "is_multipart": part.is_multipart,
        "multipart_boundary": part.multipart_boundary,
        "size": part.size,
        "role": part.role,
        "defects": [asdict(d) for d in part.defects],
        "children": [_part_tree(c) for c in part.children],
    }


def parsed_to_record_fields(parsed: ParsedMessage) -> dict[str, Any]:
    return {
        "raw_sha256": parsed.raw_sha256,
        "raw_size": parsed.raw_size,
        "message_id": parsed.message_id,
        "message_id_raw": parsed.message_id_raw,
        "date_iso": parsed.date_iso,
        "subject": parsed.subject_decoded,
        "subject_raw": parsed.subject_raw,
        "from_addr": [a.to_dict() for a in parsed.from_],
        "to_addr": [a.to_dict() for a in parsed.to],
        "cc_addr": [a.to_dict() for a in parsed.cc],
        "bcc_addr": [a.to_dict() for a in parsed.bcc],
        "sender_addr": [a.to_dict() for a in parsed.sender],
        "reply_to": [a.to_dict() for a in parsed.reply_to],
        "body_text": parsed.body_text,
        "body_html_sanitized": parsed.body_html_sanitized,
        "body_html_escaped": parsed.body_html_escaped,
        "body_part_path_text": parsed.body_part_path_text,
        "body_part_path_html": parsed.body_part_path_html,
        "part_tree": _part_tree(parsed.parts),
        "headers": parsed.headers,
        "header_summary": parsed.header_summary,
        "defects": [asdict(d) for d in parsed.defects],
        "has_errors": parsed.has_errors,
        "references": [asdict(e) for e in parsed.references],
    }


# ---------------------------------------------------------------------------
# 内存实现
# ---------------------------------------------------------------------------

class MemoryStore(ArchiveStore):
    def __init__(self, file_store: FileStore) -> None:
        self.file_store = file_store
        self.emails: dict[str, dict[str, Any]] = {}
        self.attachments: dict[str, AttachmentRow] = {}
        self.failures: dict[str, FailureRow] = {}
        self.thread_map: dict[str, str] = {}
        self.threads: dict[str, dict[str, Any]] = {}
        self.cycles: list[list[str]] = []
        self.dangling: list[dict[str, Any]] = []
        self.weak: list[dict[str, Any]] = []

    def find_by_sha(self, sha256: str) -> dict[str, Any] | None:
        for row in self.emails.values():
            if row["raw_sha256"] == sha256:
                return row
        return None

    def find_duplicate_message_ids(self, message_id: str | None, sha256: str) -> list[dict[str, Any]]:
        if not message_id:
            return []
        return [
            {"id": r["id"], "raw_sha256": r["raw_sha256"], "subject": r["subject"]}
            for r in self.emails.values()
            if r["message_id"] == message_id and r["raw_sha256"] != sha256
        ]

    def save_email(
        self,
        parsed: ParsedMessage,
        raw_blob: StoredBlob,
        attachments: list[AttachmentRow],
        duplicate_of: str | None,
        now_iso: str,
    ) -> dict[str, Any]:
        email_id = _new_id()
        record = parsed_to_record_fields(parsed)
        record.update(
            {
                "id": email_id,
                "raw_path": raw_blob.path,
                "raw_reused": raw_blob.reused,
                "duplicate_of": duplicate_of,
                "thread_id": None,
                "created_at": now_iso,
            }
        )
        self.emails[email_id] = record
        for att in attachments:
            att.email_id = email_id
            self.attachments[att.id] = att
        return record

    def add_attachments(self, email_id: str, attachments: list[AttachmentRow]) -> None:
        for att in attachments:
            att.email_id = email_id
            self.attachments[att.id] = att

    def save_failure(self, failure: FailureRow) -> None:
        self.failures[failure.id] = failure

    def _summary(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "message_id": row["message_id"],
            "message_id_raw": row["message_id_raw"],
            "date_iso": row["date_iso"],
            "subject": row["subject"],
            "from": row["from_addr"],
            "to": row["to_addr"],
            "raw_sha256": row["raw_sha256"],
            "raw_size": row["raw_size"],
            "raw_path": row["raw_path"],
            "has_errors": row["has_errors"],
            "defect_count": len(row["defects"]),
            "duplicate_of": row.get("duplicate_of"),
            "thread_id": row.get("thread_id"),
            "created_at": row["created_at"],
        }

    def get_email(self, email_id: str) -> dict[str, Any] | None:
        row = self.emails.get(email_id)
        return self._summary(row) if row else None

    def get_email_full(self, email_id: str) -> dict[str, Any] | None:
        row = self.emails.get(email_id)
        if not row:
            return None
        full = dict(row)
        full["from"] = full.get("from_addr", [])
        full["attachments"] = [asdict(self.attachments[a]) for a in self.attachments if self.attachments[a].email_id == email_id]
        return self._ensure_aliases(full)

    @staticmethod
    def _ensure_aliases(row: dict[str, Any]) -> dict[str, Any]:
        # API 的 Pydantic 模型字段名与库内列名的映射
        row.setdefault("from", row.get("from_addr", []))
        for api_name, col in (
            ("to", "to_addr"), ("cc", "cc_addr"), ("bcc", "bcc_addr"),
            ("sender", "sender_addr"),
        ):
            row.setdefault(api_name, row.get(col, []))
        return row

    def list_emails(
        self, q: str | None, message_id: str | None, limit: int, offset: int
    ) -> tuple[list[dict[str, Any]], int]:
        rows = list(self.emails.values())
        if message_id:
            rows = [r for r in rows if r["message_id"] == message_id.lower()]
        if q:
            needle = q.lower()

            def _match(row: dict[str, Any]) -> bool:
                hay = " ".join(
                    [row.get("subject") or "", row.get("body_text") or ""]
                    + [a["address"] for a in row.get("from_addr", [])]
                    + [a["address"] for a in row.get("to_addr", [])]
                ).lower()
                return needle in hay

            rows = [r for r in rows if _match(r)]
        rows.sort(key=lambda r: r.get("date_iso") or r["created_at"], reverse=True)
        total = len(rows)
        return [self._summary(r) for r in rows[offset : offset + limit]], total

    def get_attachment(self, attachment_id: str) -> AttachmentRow | None:
        return self.attachments.get(attachment_id)

    def list_attachments(self, email_id: str) -> list[AttachmentRow]:
        return [a for a in self.attachments.values() if a.email_id == email_id]

    def rebuild(self) -> dict[str, Any]:
        rows = list(self.emails.values())
        id_to_db: dict[str, str] = {}
        for r in rows:
            if r["message_id"]:
                id_to_db.setdefault(r["message_id"], r["id"])

        edges: list[tuple[str | None, str]] = []
        for r in rows:
            for ref in r["references"]:
                src = r["message_id"] if ref["kind"] == "in-reply-to" else r["message_id"]
                edges.append((src, ref["target_message_id"]))

        result = rebuild_threads([r["message_id"] for r in rows if r["message_id"]], edges)
        self.thread_map = result.members
        self.cycles = result.cycles
        self.dangling = result.dangling
        self.threads = {}
        for r in rows:
            mid = r["message_id"]
            tid = result.members.get(mid) if mid else None
            r["thread_id"] = tid
            if tid:
                bucket = self.threads.setdefault(
                    tid,
                    {"thread_id": tid, "members": [], "cycle": False, "subjects": []},
                )
                bucket["members"].append(
                    {"email_id": r["id"], "message_id": mid, "subject": r["subject"], "date_iso": r["date_iso"]}
                )
                if mid in [m for cyc in result.cycles for m in cyc]:
                    bucket["cycle"] = True
                if r["subject"]:
                    bucket["subjects"].append(r["subject"])
        for bucket in self.threads.values():
            bucket["members"].sort(key=lambda m: m.get("date_iso") or "")
        self.weak = weak_subject_candidates([(r["id"], r["subject"]) for r in rows])
        return {
            "thread_count": len(self.threads),
            "cycles": result.cycles,
            "cycle_count": len(result.cycles),
            "self_references": result.self_references,
            "dangling": result.dangling,
            "dangling_count": len(result.dangling),
            "weak_subject_candidates": self.weak,
            "weak_candidate_count": len(self.weak),
        }

    def get_thread(self, thread_id: str) -> dict[str, Any]:
        return self.threads.get(thread_id, {"thread_id": thread_id, "members": [], "found": False})

    def list_conflicts(self) -> dict[str, Any]:
        groups: dict[str, list[dict[str, Any]]] = {}
        for r in self.emails.values():
            mid = r["message_id"]
            if mid:
                groups.setdefault(mid, []).append(
                    {"email_id": r["id"], "raw_sha256": r["raw_sha256"], "subject": r["subject"], "created_at": r["created_at"]}
                )
        duplicates = [
            {"message_id": mid, "emails": items, "resolution": "retained-conflict"}
            for mid, items in groups.items()
            if len(items) > 1
        ]
        missing = [r["id"] for r in self.emails.values() if not r["message_id"]]
        return {"duplicate_message_ids": duplicates, "missing_message_ids": missing}

    def list_failures(self, limit: int) -> list[dict[str, Any]]:
        return [asdict(f) for f in list(self.failures.values())[-limit:][::-1]]

    def get_failure(self, failure_id: str) -> dict[str, Any] | None:
        f = self.failures.get(failure_id)
        return asdict(f) if f else None


def attachment_relative_path(sha256: str, extension: str) -> str:
    """与 FileStore.store_attachment 的落点保持一致（路径完全由内容决定）。"""
    from pathlib import PurePosixPath

    return str(PurePosixPath("attachments") / sha256[:2] / sha256[2:4] / (sha256 + extension))
