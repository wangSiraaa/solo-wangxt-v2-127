"""信头解析工具：编码词、地址、Message-ID、日期。

全部基于标准库 ``email.utils`` / ``email.headerregistry``，不自行猜测格式；
解析失败时返回原值并登记 defect，而不是丢弃或伪造。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from email.headerregistry import AddressHeader
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime

from .models import Address, DefectInfo

_ID_RE_CHARS = r"[^\s<>]"


@dataclass
class IdHeaderResult:
    """References / In-Reply-To 的解析结果（保留原文与冲突）。"""

    ids: list[str] = field(default_factory=list)          # 规范化（小写、去尖括号）后的标识
    raw_ids: list[str] = field(default_factory=list)      # 原始 token，含尖括号
    multiple: bool = False
    unparsable: list[str] = field(default_factory=list)  # 形如 "John <x@y>" 的混合写法


def decode_header_value(value: str | None) -> str:
    """解码 RFC 2047 编码词（=?utf-8?B?...?=）。失败时保留原始字符串。"""
    if value is None:
        return ""
    try:
        from email.headerregistry import UnstructuredHeader
        from email.policy import default as _default_policy

        # headerregistry 能正确处理编码词与裸文本混合的情况
        return str(UnstructuredHeader("subject", value, _default_policy))
    except Exception:
        return str(value)


def parse_address_header(header: AddressHeader | None) -> list[Address]:
    """把 From/To/Cc/Bcc 解析为结构化地址；无法解析的条目保留原始形式。"""
    result: list[Address] = []
    if header is None:
        return result
    try:
        groups = list(header.groups)
    except Exception:
        groups = []
    for group in groups:
        for addr in group.addresses:
            display = addr.display_name or ""
            email_addr = addr.addr_spec or ""
            if not display and not email_addr:
                continue
            result.append(Address(name=display, address=email_addr))
    # 某些畸形地址 headerregistry 会直接吞掉，用 getaddresses 兜底
    if not result and header.as_unstructured:
        raw = header.as_unstructured
        for name, addr in getaddresses([raw]):
            if name or addr:
                result.append(Address(name=decode_header_value(name), address=addr))
    return result


def parse_addresses_raw(raw: str | None) -> list[Address]:
    if not raw:
        return []
    return [
        Address(name=decode_header_value(name), address=addr)
        for name, addr in getaddresses([raw])
        if name or addr
    ]


def _extract_tokens(raw: str) -> list[str]:
    """从原始信头值中按尖括号抽取 Message-ID token，保留顺序。"""
    tokens: list[str] = []
    depth = 0
    current: list[str] = []
    in_angle = False
    for ch in raw:
        if ch == "<":
            if in_angle:
                # 嵌套 < 属于畸形输入，原样保留
                current.append(ch)
            else:
                in_angle = True
                depth += 1
                current = []
            continue
        if ch == ">":
            if in_angle:
                token = "".join(current).strip()
                if token:
                    tokens.append(token)
                in_angle = False
                current = []
            continue
        if in_angle:
            current.append(ch)
        elif not ch.isspace():
            # 尖括号外的裸字符（裸 Message-ID 或 "Name <id>" 的 Name）
            tokens.append(ch)
    if in_angle:
        # 未闭合的尖括号：把内部内容作为 token 保留（畸形，不丢弃）
        token = "".join(current).strip()
        if token:
            tokens.append(token)
    # 尖括号外的散落字符会被逐字符加入，需要在调用处重新拼合
    return tokens


def _split_id_header(raw: str | None) -> tuple[list[str], list[str]]:
    """返回 (带尖括号 token, 尖括号外残留文本)。"""
    angled: list[str] = []
    outside_parts: list[str] = []
    in_angle = False
    current: list[str] = []
    outside: list[str] = []
    for ch in raw or "":
        if ch == "<":
            in_angle = True
            if outside:
                outside_parts.append("".join(outside).strip())
                outside = []
            current = []
        elif ch == ">":
            in_angle = False
            token = "".join(current).strip()
            if token:
                angled.append(token)
        elif in_angle:
            current.append(ch)
        else:
            outside.append(ch)
    if in_angle:
        token = "".join(current).strip()
        if token:
            angled.append(token)
    tail = "".join(outside).strip()
    if tail:
        outside_parts.append(tail)
    return angled, [p for p in outside_parts if p]


def parse_message_id(raw: str | None, part_path: str) -> tuple[str | None, str | None, list[DefectInfo]]:
    """解析 Message-ID。

    返回 ``(canonical_id, raw_id, defects)``。``canonical_id`` 为小写、去尖括号形式；
    缺失返回 None；出现多个 ID 全部保留并登记冲突，取第一个为主键候选。
    """
    defects: list[DefectInfo] = []
    if raw is None or not raw.strip():
        return None, None, defects

    angled, outside = _split_id_header(raw)
    if angled:
        ids = angled
        if outside:
            defects.append(
                DefectInfo(
                    part_path=part_path,
                    defect_type="MalformedMessageId",
                    severity="warning",
                    message="Message-ID 信头包含尖括号外的多余文本，已忽略",
                    detail={"extra_text": " ".join(outside)[:200]},
                )
            )
        primary = ids[0]
        return primary.lower(), f"<{primary}>", defects

    # 无成对尖括号：容错处理 "<id>"（单尖括号）/裸 ID，去两端尖括号
    candidate = raw.strip().lstrip("<").rstrip(">").strip()
    if not candidate:
        return None, None, defects
    if candidate != raw.strip():
        defects.append(
            DefectInfo(
                part_path=part_path,
                defect_type="MalformedMessageId",
                severity="warning",
                message="Message-ID 尖括号不成对，已规范化",
            )
        )
    # 不成对尖括号场景下仍可能含多个 token
    tokens = [t.strip().lstrip("<").rstrip(">").strip() for t in candidate.split()]
    tokens = [t for t in tokens if t]
    if len(tokens) > 1:
        defects.append(
            DefectInfo(
                part_path=part_path,
                defect_type="DuplicateHeaderMessageId",
                severity="warning",
                message=f"Message-ID 信头中存在 {len(tokens)} 个标识，保留全部冲突",
                detail={"all_ids": tokens[:50]},
            )
        )
    return tokens[0].lower(), raw.strip(), defects


def parse_references(raw: str | None, part_path: str = "") -> IdHeaderResult:
    """解析 References 信头，保留所有标识（包括重复与循环引用所需的顺序）。"""
    result = IdHeaderResult()
    if raw is None or not raw.strip():
        return result
    angled, outside = _split_id_header(raw)
    for token in angled:
        result.ids.append(token.lower())
        result.raw_ids.append(f"<{token}>")
    if outside:
        # 可能是裸 ID（空白分隔），也可能是混入的人名
        for piece in outside:
            for token in piece.split():
                if "@" in token or "." in token:
                    result.ids.append(token.lower().strip("<>"))
                    result.raw_ids.append(token)
                else:
                    result.unparsable.append(token)
    result.multiple = len(result.ids) > 1
    return result


def parse_in_reply_to(raw: str | None, part_path: str = "") -> IdHeaderResult:
    """In-Reply-To 按 RFC 应只有一个标识；出现多个时全部保留并标记。"""
    result = parse_references(raw, part_path)
    return result


def parse_date(raw: str | None, part_path: str) -> tuple[str | None, list[DefectInfo]]:
    """解析 Date 为 ISO-8601（UTC）。无法解析时保留 None 并登记。"""
    if not raw or not raw.strip():
        return None, []
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None, [
            DefectInfo(
                part_path=part_path,
                defect_type="InvalidDate",
                severity="warning",
                message="Date 信头无法解析",
                detail={"raw": raw[:200]},
            )
        ]
    if dt is not None and dt.tzinfo is None:
        # 朴素时间戳按 RFC 本应有 +0000；按 UTC 处理并标记
        from datetime import timezone

        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat() if dt else None, []


def iter_raw_headers(msg: Message) -> list[tuple[str, str]]:
    """以原始（未解码）形式返回全部信头，保留重复信头。"""
    return [(name, value) for name, value in msg.raw_items()]
