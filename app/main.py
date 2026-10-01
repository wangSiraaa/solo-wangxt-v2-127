"""企业邮件档案 HTTP API（无前端）。

端点：
  POST /api/v1/emails                上传 EML 摄取
  GET  /api/v1/emails                列表 / 检索
  GET  /api/v1/emails/{id}           邮件事实详情（结构树/信头/正文/缺陷）
  GET  /api/v1/emails/{id}/raw       下载原始 EML（attachment 方式，不内联渲染）
  GET  /api/v1/attachments/{id}      附件元数据
  GET  /api/v1/attachments/{id}/raw  下载附件（受控目录校验 + 安全文件名）
  POST /api/v1/threads/rebuild       重建会话图
  GET  /api/v1/threads/{id}          会话详情
  GET  /api/v1/conflicts             Message-ID 重复/缺失清单（保留冲突）
  GET  /api/v1/failures              解析失败列表
  GET  /api/v1/failures/{id}         失败定位（含 quarantine 路径）
  GET  /healthz
"""
from __future__ import annotations

import contextlib
import mimetypes
import urllib.parse
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, Response

from .config import settings
from .logging_config import configure_logging, get_logger
from .schemas import (
    ConflictsResponse,
    EmailDetail,
    FailureOut,
    HealthResponse,
    IngestResponse,
    ListEmailsResponse,
    RebuildResponse,
    ThreadResponse,
)
from .service import ArchiveService, IngestError
from .storage import (
    ArchiveStore,
    FileStore,
    PathTraversalError,
    create_store,
)

configure_logging()
log = get_logger("api")

_state: dict[str, object] = {}


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_dirs()
    file_store = FileStore(settings.storage_dir)
    store = create_store(settings.database_url, file_store)
    _state["file_store"] = file_store
    _state["store"] = store
    _state["service"] = ArchiveService(
        store, file_store, auto_rebuild=settings.auto_rebuild_threads
    )
    log.info("backend ready postgres=%s storage=%s", bool(settings.use_postgres), settings.storage_dir)
    try:
        yield
    finally:
        close = getattr(store, "close", None)
        if callable(close):
            close()
        _state.clear()


app = FastAPI(
    title="Enterprise Mail Archive",
    version="1.0.0",
    description="EML -> 可检索邮件事实。信头/关系存 PostgreSQL，附件落受控目录。",
    lifespan=lifespan,
)


def get_filestore() -> FileStore:
    return _state["file_store"]  # type: ignore[return-value]


def get_store() -> ArchiveStore:
    return _state["store"]  # type: ignore[return-value]


def get_service() -> ArchiveService:
    return _state["service"]  # type: ignore[return-value]


def _content_disposition(filename: str) -> str:
    ascii_name = filename.encode("ascii", "ignore").decode() or "attachment.bin"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(filename)}"


# ---------------------------------------------------------------------------
# 摄取
# ---------------------------------------------------------------------------

@app.post("/api/v1/emails", response_model=IngestResponse, status_code=201,
          summary="上传并解析一封 EML")
async def ingest_email(
    request: Request,
    eml: UploadFile,
    service: Annotated[ArchiveService, Depends(get_service)],
) -> IngestResponse:
    raw = await eml.read()
    if settings.max_upload_bytes and len(raw) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"EML 超过大小限制（{settings.max_upload_bytes} 字节）",
        )
    try:
        result = service.ingest(raw, declared_filename=eml.filename)
    except IngestError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.payload or str(exc))
    return IngestResponse(**result)


# ---------------------------------------------------------------------------
# 检索与详情
# ---------------------------------------------------------------------------

def _normalize_message_id(value: str | None) -> str | None:
    """查询参数里的 Message-ID 规范化为小写、去尖括号。"""
    if value is None:
        return None
    v = value.strip().lstrip("<").rstrip(">").strip().lower()
    return v or None


@app.get("/api/v1/emails", response_model=ListEmailsResponse, summary="列表/检索邮件")
def list_emails(
    store: Annotated[ArchiveStore, Depends(get_store)],
    q: Annotated[str | None, Query(description="主题/正文/地址全文检索词")] = None,
    message_id: Annotated[str | None, Query(description="按规范化 Message-ID 精确过滤（尖括号可省略）")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ListEmailsResponse:
    items, total = store.list_emails(q, _normalize_message_id(message_id), limit, offset)
    return ListEmailsResponse(total=total, limit=limit, offset=offset, items=items)  # type: ignore[arg-type]


@app.get("/api/v1/emails/{email_id}", response_model=EmailDetail, summary="邮件事实详情")
def get_email(email_id: str, store: Annotated[ArchiveStore, Depends(get_store)]) -> EmailDetail:
    row = store.get_email_full(email_id)
    if not row:
        raise HTTPException(404, "邮件不存在")
    return EmailDetail(**row)  # type: ignore[arg-type]


@app.get("/api/v1/emails/{email_id}/raw", summary="下载原始 EML")
def get_raw_email(
    email_id: str,
    store: Annotated[ArchiveStore, Depends(get_store)],
    file_store: Annotated[FileStore, Depends(get_filestore)],
) -> FileResponse:
    row = store.get_email_full(email_id)
    if not row:
        raise HTTPException(404, "邮件不存在")
    try:
        path, size = file_store.open_blob(row["raw_path"])
    except (PathTraversalError, FileNotFoundError):
        raise HTTPException(404, "原始文件不可用")
    return FileResponse(
        path,
        media_type="message/rfc822",
        filename=f"{row['raw_sha256'][:16]}.eml",
        content_disposition_type="attachment",
    )


# ---------------------------------------------------------------------------
# 附件
# ---------------------------------------------------------------------------

@app.get("/api/v1/attachments/{attachment_id}", summary="附件元数据")
def get_attachment_meta(
    attachment_id: str, store: Annotated[ArchiveStore, Depends(get_store)]
) -> dict:
    att = store.get_attachment(attachment_id)
    if not att:
        raise HTTPException(404, "附件不存在")
    return {
        "id": att.id, "email_id": att.email_id, "sha256": att.sha256,
        "relative_path": att.relative_path, "original_filename": att.original_filename,
        "safe_filename": att.safe_filename, "content_type": att.content_type,
        "content_id": att.content_id, "content_location": att.content_location,
        "disposition": att.disposition, "kind": att.kind, "size": att.size,
        "part_path": att.part_path,
    }


@app.get("/api/v1/attachments/{attachment_id}/raw", summary="下载附件字节")
def get_attachment_bytes(
    attachment_id: str,
    store: Annotated[ArchiveStore, Depends(get_store)],
    file_store: Annotated[FileStore, Depends(get_filestore)],
) -> Response:
    att = store.get_attachment(attachment_id)
    if not att:
        raise HTTPException(404, "附件不存在")
    try:
        path, size = file_store.open_blob(att.relative_path)
    except PathTraversalError:
        # 元数据里的路径若被人为改成逃逸路径，必须显式拒绝
        log.warning("attachment path traversal blocked attachment_id=%s", attachment_id)
        raise HTTPException(403, "拒绝越界路径")
    except FileNotFoundError:
        raise HTTPException(404, "附件文件缺失")
    media_type = att.content_type if att.content_type and "/" in att.content_type else (
        mimetypes.guess_type(att.safe_filename)[0] or "application/octet-stream"
    )
    # 统一强制 attachment：HTML/SVG 等也不内联，杜绝存储型脚本在应用上下文执行
    headers = {"Content-Disposition": _content_disposition(att.safe_filename)}
    return FileResponse(path, media_type=media_type, headers=headers)


# ---------------------------------------------------------------------------
# 会话
# ---------------------------------------------------------------------------

@app.post("/api/v1/threads/rebuild", response_model=RebuildResponse, summary="重建会话图")
def rebuild_threads(store: Annotated[ArchiveStore, Depends(get_store)]) -> RebuildResponse:
    return RebuildResponse(**store.rebuild())


@app.get("/api/v1/threads/{thread_id}", response_model=ThreadResponse, summary="会话详情")
def get_thread(thread_id: str, store: Annotated[ArchiveStore, Depends(get_store)]) -> ThreadResponse:
    return ThreadResponse(**store.get_thread(thread_id))


# ---------------------------------------------------------------------------
# 冲突与失败
# ---------------------------------------------------------------------------

@app.get("/api/v1/conflicts", response_model=ConflictsResponse,
         summary="Message-ID 重复/缺失冲突清单（保留不合并）")
def list_conflicts(store: Annotated[ArchiveStore, Depends(get_store)]) -> ConflictsResponse:
    return ConflictsResponse(**store.list_conflicts())


@app.get("/api/v1/failures", response_model=list[FailureOut], summary="解析失败列表")
def list_failures(
    store: Annotated[ArchiveStore, Depends(get_store)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[FailureOut]:
    return [FailureOut(**f) for f in store.list_failures(limit)]  # type: ignore[arg-type]


@app.get("/api/v1/failures/{failure_id}", response_model=FailureOut, summary="解析失败定位")
def get_failure(failure_id: str, store: Annotated[ArchiveStore, Depends(get_store)]) -> FailureOut:
    row = store.get_failure(failure_id)
    if not row:
        raise HTTPException(404, "失败记录不存在")
    return FailureOut(**row)  # type: ignore[arg-type]


@app.get("/healthz", response_model=HealthResponse, tags=["meta"])
def healthz() -> HealthResponse:
    return HealthResponse(
        status="ok",
        backend="postgres" if settings.use_postgres else "memory",
        storage_dir=str(settings.storage_dir),
    )
