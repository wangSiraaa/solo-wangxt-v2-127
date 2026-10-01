"""解析层的数据结构（不依赖数据库与 Web 层）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Address:
    name: str
    address: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "address": self.address}


@dataclass
class DefectInfo:
    """解析缺陷/异常。part_path 精确定位到 MIME 部件。"""

    part_path: str
    defect_type: str
    severity: str  # "warning" | "error"
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttachmentPayload:
    """附件/内嵌资源的解码结果（仅在摄取阶段存活，不进日志）。"""

    filename: str | None
    payload: bytes
    content_type: str
    content_id: str | None
    content_location: str | None
    disposition: str | None  # attachment / inline / None
    kind: str  # attachment / inline
    size: int
    part_path: str


@dataclass
class PartInfo:
    """MIME 结构树节点，反映多层 MIME 的真实结构。"""

    part_path: str
    content_type: str
    disposition: str | None
    filename: str | None
    content_id: str | None
    content_location: str | None
    charset: str | None
    is_multipart: bool
    multipart_boundary: str | None
    size: int
    role: str  # multipart / body / inline / attachment / other
    children: list["PartInfo"] = field(default_factory=list)
    defects: list[DefectInfo] = field(default_factory=list)


@dataclass
class ReferenceEdge:
    """邮件之间的会话边，完整保留 References / In-Reply-To。"""

    kind: str  # in-reply-to / references
    target_message_id: str
    ordinal: int
    raw: str | None


@dataclass
class ParsedMessage:
    raw_sha256: str
    raw_size: int
    message_id: str | None
    message_id_raw: str | None
    date_iso: str | None
    subject_decoded: str
    subject_raw: str | None
    from_: list[Address]
    to: list[Address]
    cc: list[Address]
    bcc: list[Address]
    sender: list[Address]
    reply_to: list[Address]
    body_text: str
    body_html_sanitized: str
    body_html_escaped: str
    body_part_path_text: str | None
    body_part_path_html: str | None
    parts: PartInfo
    attachments: list[AttachmentPayload]
    headers: list[dict[str, Any]]
    header_summary: list[dict[str, Any]]
    references: list[ReferenceEdge]
    defects: list[DefectInfo]
    has_errors: bool
