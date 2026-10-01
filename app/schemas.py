"""API 响应模型（Pydantic v2）。"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AddressOut(BaseModel):
    name: str = ""
    address: str = ""


class DefectOut(BaseModel):
    part_path: str
    defect_type: str
    severity: str
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)


class AttachmentSummaryOut(BaseModel):
    id: str
    part_path: str
    kind: str
    filename: str | None = None
    size: int
    content_type: str
    content_id: str | None = None
    sha256: str


class IngestResponse(BaseModel):
    status: str
    email_id: str | None = None
    raw_sha256: str
    raw_path: str | None = None
    message_id: str | None = None
    duplicate_of: str | None = None
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    attachments: list[AttachmentSummaryOut] = Field(default_factory=list)
    defects: list[dict[str, Any]] = Field(default_factory=list)
    has_errors: bool = False
    thread_rebuild: dict[str, Any] | None = None


class EmailSummary(BaseModel):
    id: str
    message_id: str | None = None
    message_id_raw: str | None = None
    date_iso: str | None = None
    subject: str | None = None
    from_: list[AddressOut] = Field(default_factory=list, alias="from")
    to: list[AddressOut] = Field(default_factory=list)
    raw_sha256: str
    raw_size: int
    raw_path: str
    has_errors: bool
    defect_count: int
    duplicate_of: str | None = None
    thread_id: str | None = None
    created_at: str | None = None

    model_config = {"populate_by_name": True}


class ListEmailsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[EmailSummary]


class AttachmentOut(BaseModel):
    id: str
    email_id: str
    sha256: str
    relative_path: str
    original_filename: str | None = None
    safe_filename: str
    content_type: str
    content_id: str | None = None
    content_location: str | None = None
    disposition: str | None = None
    kind: str
    size: int
    part_path: str


class EmailDetail(BaseModel):
    id: str
    message_id: str | None = None
    message_id_raw: str | None = None
    date_iso: str | None = None
    subject: str | None = None
    subject_raw: str | None = None
    from_: list[AddressOut] = Field(default_factory=list, alias="from")
    to: list[AddressOut] = Field(default_factory=list)
    cc: list[AddressOut] = Field(default_factory=list)
    bcc: list[AddressOut] = Field(default_factory=list)
    sender: list[AddressOut] = Field(default_factory=list)
    reply_to: list[AddressOut] = Field(default_factory=list)
    body_text: str = ""
    body_html_sanitized: str = ""
    body_html_escaped: str = ""
    body_part_path_text: str | None = None
    body_part_path_html: str | None = None
    part_tree: dict[str, Any] = Field(default_factory=dict)
    headers: list[dict[str, Any]] = Field(default_factory=list)
    defects: list[DefectOut] = Field(default_factory=list)
    has_errors: bool
    references: list[dict[str, Any]] = Field(default_factory=list)
    attachments: list[AttachmentOut] = Field(default_factory=list)
    raw_sha256: str
    raw_size: int
    raw_path: str
    raw_reused: bool = False
    duplicate_of: str | None = None
    thread_id: str | None = None
    created_at: str | None = None

    model_config = {"populate_by_name": True}


class FailureOut(BaseModel):
    id: str
    raw_sha256: str
    raw_size: int
    stage: str
    error_type: str
    message: str
    quarantine_path: str | None = None
    created_at: str | None = None


class RebuildResponse(BaseModel):
    thread_count: int
    cycles: list[list[str]]
    cycle_count: int
    self_references: list[str]
    dangling: list[dict[str, Any]]
    dangling_count: int
    weak_subject_candidates: list[dict[str, Any]]
    weak_candidate_count: int


class ThreadResponse(BaseModel):
    thread_id: str
    cycle: bool = False
    found: bool = True
    members: list[dict[str, Any]] = Field(default_factory=list)


class ConflictsResponse(BaseModel):
    duplicate_message_ids: list[dict[str, Any]]
    missing_message_ids: list[str]


class HealthResponse(BaseModel):
    status: str
    backend: str
    storage_dir: str
