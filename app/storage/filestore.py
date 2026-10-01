"""受控目录文件存储。

安全约束：
* 附件按 SHA-256 内容寻址落盘（aa/bb/<sha>.<ext>），不信任客户端/EML 中的文件名；
* 每次写入/读取都用 ``_resolve_inside`` 校验最终路径在受控根目录内，
  任何 ``..``、绝对路径、符号链接逃逸都会抛 PathTraversalError；
* 原 EML 与隔离文件分别放在 raw/quarantine 子树；
* 写入走临时文件 + os.replace 原子替换；
* 本模块的日志绝不记录载荷内容，只记录 sha/大小/类型。
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..logging_config import get_logger

log = get_logger("filestore")


class PathTraversalError(Exception):
    """解析后的真实路径逃出受控根目录。"""


class StorageError(Exception):
    pass


_SAFE_NAME_RE = re.compile(r"[\x00-\x1f/\\:*?\"<>|]+", re.UNICODE)
_DOT_EXT_RE = re.compile(r"^\.[A-Za-z0-9]{1,12}$")
_EXT_FALLBACK = {
    "image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif",
    "text/plain": ".txt", "text/html": ".html", "application/pdf": ".pdf",
    "application/zip": ".zip",
}


def sanitize_filename(filename: str | None, content_type: str | None = None) -> str:
    """把 EML/客户端提供的文件名转为安全的存储用名。

    不参与路径决策（路径只用 sha），仅用于展示与下载文件名。
    保留空格、中文、括号等可读字符；只移除路径分隔符、控制字符与平台非法字符。
    """
    name = (filename or "").replace("\x00", "")
    # 只取最后一段，拦掉任何目录成分（含 Windows 的 \\）
    name = re.split(r"[\\/]", name)[-1].strip()
    # 纯点串或前导点：".hidden"/"..." 不构成有意义的文件名，整体视为无名
    if not name or set(name) == {"."} or name.startswith("."):
        ct = (content_type or "").split(";")[0].strip().lower()
        return "unnamed" + _EXT_FALLBACK.get(ct, ".bin")
    if "." in name:
        stem, _, ext = name.rpartition(".")
    else:
        stem, ext = name, ""
    safe_stem = _SAFE_NAME_RE.sub("_", stem).strip(" ._-")[:120]
    safe_ext = "." + ext.lower() if ext and _DOT_EXT_RE.match("." + ext) else ""
    if not safe_stem:
        ct = (content_type or "").split(";")[0].strip().lower()
        return "unnamed" + (safe_ext or _EXT_FALLBACK.get(ct, ".bin"))
    return safe_stem + safe_ext


def safe_extension(filename: str | None, content_type: str | None = None) -> str:
    cleaned = sanitize_filename(filename, content_type)
    if "." in cleaned:
        ext = "." + cleaned.rsplit(".", 1)[1]
        if _DOT_EXT_RE.match(ext):
            return ext
    return ".bin"


@dataclass(frozen=True)
class StoredBlob:
    sha256: str
    path: str          # 相对受控根目录的路径
    size: int
    reused: bool       # 相同内容已存在（去重）


class FileStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.attachments_dir = self.root / "attachments"
        self.raw_dir = self.root / "raw"
        self.quarantine_dir = self.root / "quarantine"
        for path in (self.root, self.attachments_dir, self.raw_dir, self.quarantine_dir):
            path.mkdir(parents=True, exist_ok=True)

    # -- 路径安全 --------------------------------------------------------
    def _resolve_inside(self, base: Path, *parts: str) -> Path:
        """拼接并校验最终 realpath 必须位于 base 之下。"""
        base_real = Path(base).resolve()
        candidate = base_real.joinpath(*parts)
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise PathTraversalError(f"路径无法解析: {exc.__class__.__name__}") from exc
        # is_relative_to 自 3.9 可用；额外保留 commonpath 双保险
        inside = resolved == base_real or base_real in resolved.parents
        if not inside:
            raise PathTraversalError("拒绝访问受控目录之外的路径")
        if resolved.is_symlink():
            raise PathTraversalError("拒绝通过符号链接访问")
        return resolved

    # -- 写入 ------------------------------------------------------------
    def _atomic_write(self, target: Path, data: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(target.parent))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def store_attachment(self, payload: bytes, sha256: str, extension: str) -> StoredBlob:
        if not _DOT_EXT_RE.match(extension if extension.startswith(".") else f".{extension}"):
            extension = ".bin"
        rel_parts = ("attachments", sha256[:2], sha256[2:4], sha256 + extension)
        target = self._resolve_inside(self.root, *rel_parts)
        reused = target.exists()
        if not reused:
            self._atomic_write(target, payload)
            log.info("attachment stored sha=%s size=%d reused=false", sha256, len(payload))
        else:
            log.info("attachment dedup sha=%s size=%d reused=true", sha256, len(payload))
        return StoredBlob(sha256, str(Path(*rel_parts)), len(payload), reused)

    def store_raw(self, payload: bytes, sha256: str) -> StoredBlob:
        rel_parts = ("raw", sha256[:2], sha256[2:4], sha256 + ".eml")
        target = self._resolve_inside(self.root, *rel_parts)
        reused = target.exists()
        if not reused:
            self._atomic_write(target, payload)
        log.info("raw eml stored sha=%s size=%d reused=%s", sha256, len(payload), reused)
        return StoredBlob(sha256, str(Path(*rel_parts)), len(payload), reused)

    def store_quarantine(self, payload: bytes, failure_id: str) -> StoredBlob:
        safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", failure_id)
        sha256 = hashlib.sha256(payload).hexdigest()
        rel_parts = ("quarantine", safe_id[:2], safe_id + ".eml")
        target = self._resolve_inside(self.root, *rel_parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write(target, payload)
        log.info("quarantined eml failure_id=%s sha=%s size=%d", safe_id, sha256, len(payload))
        return StoredBlob(sha256, str(Path(*rel_parts)), len(payload), False)

    # -- 读取 ------------------------------------------------------------
    def open_blob(self, relative_path: str) -> tuple[Path, int]:
        """按相对路径打开受控根内的 blob，返回 (绝对路径, 大小)。"""
        normalized = relative_path.replace("\\", "/")
        parts = [p for p in normalized.split("/") if p not in ("", ".")]
        if not parts:
            raise PathTraversalError("空路径")
        if normalized.startswith("/") or any(p == ".." for p in parts):
            raise PathTraversalError("路径中不允许绝对路径或 ..")
        target = self._resolve_inside(self.root, *parts)
        if not target.is_file():
            raise FileNotFoundError(relative_path)
        return target, target.stat().st_size

    def read_raw(self, sha256: str) -> bytes:
        target = self._resolve_inside(
            self.root, "raw", sha256[:2], sha256[2:4], sha256 + ".eml"
        )
        if not target.is_file():
            raise FileNotFoundError(sha256)
        return target.read_bytes()
