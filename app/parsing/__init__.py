"""解析层：EML -> ParsedMessage（无副作用、无 I/O）。"""
from .eml_parser import FatalParseError, parse_eml
from .models import (
    Address,
    AttachmentPayload,
    DefectInfo,
    ParsedMessage,
    PartInfo,
    ReferenceEdge,
)
from .sanitizer import SanitizeResult, sanitize_html
from .threads import (
    rebuild_threads,
    subject_weak_key,
    weak_subject_candidates,
)

__all__ = [
    "parse_eml",
    "FatalParseError",
    "sanitize_html",
    "SanitizeResult",
    "Address",
    "AttachmentPayload",
    "DefectInfo",
    "ParsedMessage",
    "PartInfo",
    "ReferenceEdge",
    "rebuild_threads",
    "subject_weak_key",
    "weak_subject_candidates",
]
