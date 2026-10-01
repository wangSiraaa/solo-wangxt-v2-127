"""摄取编排：解析 -> 受控落盘 -> 元数据入库 -> 会话重建。

关键策略：
* 相同 SHA-256 的 EML 视为完全重复，直接复用记录，不重复落盘；
* Message-ID 相同但内容不同：保留两条记录，后到者标记 duplicate_of，不合并；
* 缺失 Message-ID：照常入库，仅登记在冲突清单中，不生成伪 ID 合并；
* 解析致命错误：原文件进 quarantine/，失败记录可按 id 定位；
* 附件内容绝不传入日志（日志只出现 sha/路径/大小）。
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict
from datetime import datetime, timezone

from .logging_config import get_logger
from .parsing import FatalParseError, parse_eml
from .storage.archive import (
    ArchiveStore,
    AttachmentRow,
    FailureRow,
)
from .storage.filestore import FileStore, PathTraversalError, safe_extension, sanitize_filename

log = get_logger("service")


class IngestError(Exception):
    def __init__(self, message: str, *, status_code: int = 422, payload: dict | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload or {}


class ArchiveService:
    def __init__(self, store: ArchiveStore, file_store: FileStore, *, auto_rebuild: bool = True) -> None:
        self.store = store
        self.file_store = file_store
        self.auto_rebuild = auto_rebuild

    def ingest(self, raw: bytes, *, declared_filename: str | None = None) -> dict:
        sha256 = hashlib.sha256(raw).hexdigest()

        existing = self.store.find_by_sha(sha256)
        if existing:
            log.info("identical eml already present sha=%s email_id=%s", sha256, existing["id"])
            return {"status": "duplicate-content", "email_id": existing["id"], "raw_sha256": sha256}

        # 先解析（不落盘），致命错误走隔离
        try:
            parsed = parse_eml(raw)
        except FatalParseError as exc:
            return self._quarantine(raw, sha256, exc.stage, exc)
        except Exception as exc:  # 解析器之外的意外也要隔离且不泄漏载荷
            log.exception("unexpected parser failure sha=%s stage=unknown", sha256)
            return self._quarantine(raw, sha256, "unknown", exc)

        # 原 EML 落盘
        raw_blob = self.file_store.store_raw(raw, sha256)

        # Message-ID 冲突检测：相同 ID、不同内容 -> 保留冲突，不合并
        dupes = self.store.find_duplicate_message_ids(parsed.message_id, sha256)
        duplicate_of = dupes[0]["id"] if dupes else None
        if dupes:
            log.warning(
                "message-id conflict id=%s conflicting_with=%d-record(s), retained",
                parsed.message_id,
                len(dupes),
            )

        now = datetime.now(timezone.utc).isoformat()

        # 附件落盘（内容寻址，文件名不参与路径）。逐件记录失败而不影响整封入库。
        attachment_rows: list[AttachmentRow] = []
        for att in parsed.attachments:
            ext = safe_extension(att.filename, att.content_type)
            att_sha = hashlib.sha256(att.payload).hexdigest()
            try:
                blob = self.file_store.store_attachment(att.payload, att_sha, ext)
            except PathTraversalError:
                log.error("attachment path traversal blocked part=%s", att.part_path)
                continue
            attachment_rows.append(
                AttachmentRow(
                    id=str(uuid.uuid4()),
                    email_id="",  # save_email 时回填
                    sha256=blob.sha256,
                    relative_path=blob.path,
                    original_filename=att.filename,
                    safe_filename=sanitize_filename(att.filename, att.content_type),
                    content_type=att.content_type,
                    content_id=att.content_id,
                    content_location=att.content_location,
                    disposition=att.disposition,
                    kind=att.kind,
                    size=att.size,
                    part_path=att.part_path,
                )
            )

        record = self.store.save_email(
            parsed=parsed,
            raw_blob=raw_blob,
            attachments=attachment_rows,
            duplicate_of=duplicate_of,
            now_iso=now,
        )

        log.info(
            "ingested email_id=%s mid=%s attachments=%d defects=%d errors=%s",
            record["id"], parsed.message_id, len(attachment_rows),
            len(parsed.defects), parsed.has_errors,
        )

        rebuild_info = None
        if self.auto_rebuild:
            rebuild_info = self.store.rebuild()

        return {
            "status": "conflict-retained" if duplicate_of else "ingested",
            "email_id": record["id"],
            "raw_sha256": sha256,
            "raw_path": raw_blob.path,
            "message_id": parsed.message_id,
            "duplicate_of": duplicate_of,
            "conflicts": dupes,
            "attachments": [
                {
                    "id": r.id, "part_path": r.part_path, "kind": r.kind,
                    "filename": r.safe_filename, "size": r.size,
                    "content_type": r.content_type, "content_id": r.content_id,
                    "sha256": r.sha256,
                }
                for r in attachment_rows
            ],
            "defects": [asdict(d) for d in parsed.defects],
            "has_errors": parsed.has_errors,
            "thread_rebuild": rebuild_info,
        }

    def _quarantine(self, raw: bytes, sha256: str, stage: str, exc: Exception) -> dict:
        failure_id = str(uuid.uuid4())
        try:
            blob = self.file_store.store_quarantine(raw, failure_id)
            quarantine_path = blob.path
        except Exception:
            log.exception("quarantine write failed failure_id=%s sha=%s", failure_id, sha256)
            quarantine_path = None
        failure = FailureRow(
            id=failure_id,
            raw_sha256=sha256,
            raw_size=len(raw),
            stage=stage,
            error_type=type(exc).__name__,
            message=str(exc)[:500],
            quarantine_path=quarantine_path,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.store.save_failure(failure)
        log.warning("parse failure isolated failure_id=%s sha=%s stage=%s error=%s",
                    failure_id, sha256, stage, type(exc).__name__)
        raise IngestError(
            "EML 解析失败，原始文件已隔离",
            status_code=422,
            payload={
                "status": "failed",
                "failure_id": failure_id,
                "raw_sha256": sha256,
                "stage": stage,
                "error_type": type(exc).__name__,
                "quarantine_path": quarantine_path,
            },
        )
