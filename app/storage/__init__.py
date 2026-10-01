"""存储层：受控目录文件存储 + 元数据后端（内存 / PostgreSQL）。"""
from .archive import (
    ArchiveStore,
    AttachmentRow,
    FailureRow,
    MemoryStore,
    attachment_relative_path,
    parsed_to_record_fields,
)
from .filestore import (
    FileStore,
    PathTraversalError,
    StoredBlob,
    sanitize_filename,
)


def create_store(dsn: str, file_store: FileStore) -> ArchiveStore:
    if dsn:
        from .postgres import PostgresStore

        return PostgresStore(dsn)
    return MemoryStore(file_store)


__all__ = [
    "ArchiveStore",
    "MemoryStore",
    "AttachmentRow",
    "FailureRow",
    "FileStore",
    "PathTraversalError",
    "StoredBlob",
    "sanitize_filename",
    "create_store",
    "attachment_relative_path",
    "parsed_to_record_fields",
]
