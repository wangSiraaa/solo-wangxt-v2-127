"""运行期配置，全部来自环境变量，缺省时退回内存后端，便于本地与 CI 运行。"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # 受控存储根目录：附件与原 EML 只能写在这个目录之下
    storage_dir: Path = Path(_env("MAIL_ARCHIVE_HOME", "/workspace/data"))
    database_url: str = _env("MAIL_ARCHIVE_DSN", "")
    # 0 表示不限制
    max_upload_bytes: int = _env_int("MAIL_ARCHIVE_MAX_BYTES", 50 * 1024 * 1024)
    # 解析出致命错误后，原始文件隔离存放的相对目录
    quarantine_dirname: str = "quarantine"
    raw_dirname: str = "raw"
    attachments_dirname: str = "attachments"
    # 是否在摄取后立即重建会话图（关闭时可由定时任务/手动接口触发）
    auto_rebuild_threads: bool = _env_bool("MAIL_ARCHIVE_REBUILD_THREADS", True)

    @property
    def attachments_dir(self) -> Path:
        return self.storage_dir / self.attachments_dirname

    @property
    def raw_dir(self) -> Path:
        return self.storage_dir / self.raw_dirname

    @property
    def quarantine_dir(self) -> Path:
        return self.storage_dir / self.quarantine_dirname

    @property
    def use_postgres(self) -> bool:
        return bool(self.database_url)

    def ensure_dirs(self) -> None:
        for path in (self.attachments_dir, self.raw_dir, self.quarantine_dir):
            path.mkdir(parents=True, exist_ok=True)


settings = Settings()
