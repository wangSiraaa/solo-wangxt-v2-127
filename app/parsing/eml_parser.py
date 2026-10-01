"""EML 解析器（核心模块，纯函数，不接触数据库/文件系统/日志）。

设计要点见 README：
* ``policy.default`` + 手动递归，拿到每个 MIME 部件的 defects 与路径；
* 多层 multipart/mixed|alternative|related|signed 按真实树结构保留；
* 字符集按声明解码并多档回退，绝不丢正文；
* 附件（attachment）与内嵌资源（inline + Content-ID）分开标记；
* Message-ID / References / In-Reply-To 完整保留，重复与缺失交给上层处理；
* 解析失败以 DefectInfo(part_path, ...) 返回，可定位到部件；
  致命异常向上抛 FatalParseError，由服务层隔离原始文件。
"""
from __future__ import annotations

import hashlib
import re
from email.message import EmailMessage, MIMEPart
from email.parser import BytesParser
from email.policy import default as default_policy

from .headers import (
    decode_header_value,
    iter_raw_headers,
    parse_address_header,
    parse_addresses_raw,
    parse_date,
    parse_in_reply_to,
    parse_message_id,
    parse_references,
)
from .models import (
    Address,
    AttachmentPayload,
    DefectInfo,
    PartInfo,
    ParsedMessage,
    ReferenceEdge,
)
from .sanitizer import sanitize_html

# 与 email.errors 中缺陷类型的严重程度映射：
# 无法确定结构/编码的为 error，其余为 warning
_ERROR_DEFECT_TYPES = {
    "MultipartInvariantViolationDefect",
    "StartBoundaryNotFoundDefect",
    "CloseBoundaryNotFoundDefect",
    "InvalidMultipartContentSeparator",
    "InvalidBoundaryError",
    "NoBoundaryInMultipartDefect",
    "MalformedInReplyToDefect",
    "MalformedMessageIdDefect",
    "MalformedAddress",
    "ObsoleteHeaderDefect",
    "NonPrintableDefect",
}


class FatalParseError(Exception):
    """整个 EML 无法解析（例如完全不是 RFC822 数据）。"""

    def __init__(self, message: str, *, stage: str) -> None:
        super().__init__(message)
        self.stage = stage


def _severity(defect: Exception) -> str:
    return "error" if type(defect).__name__ in _ERROR_DEFECT_TYPES else "warning"


def _defects_of(part: MIMEPart, part_path: str) -> list[DefectInfo]:
    out: list[DefectInfo] = []
    for defect in getattr(part, "defects", []) or []:
        name = type(defect).__name__
        msg = str(defect) or name
        out.append(
            DefectInfo(
                part_path=part_path,
                defect_type=name,
                severity=_severity(defect),
                message=msg,
            )
        )
    return out


def _content_charset(part: MIMEPart) -> str | None:
    try:
        return part.get_content_charset()
    except (LookupError, TypeError):
        return None


def _decode_text(part: MIMEPart, part_path: str, charset: str | None) -> tuple[str, list[DefectInfo]]:
    """优先 get_content（会触发 base64/QP/字符集解码与缺陷登记），多档回退。"""
    defects: list[DefectInfo] = []
    try:
        text = part.get_content()
        if isinstance(text, str):
            if charset:
                try:
                    # 重新按声明字符集验证一次，确保结果正确
                    raw = part.get_payload(decode=True)
                    if raw is not None:
                        text = raw.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    defects.append(
                        DefectInfo(part_path, "UnknownCharset", "warning",
                                  f"声明的字符集 {charset!r} 不可用，已回退")
                    )
            return text, defects
        # get_content 返回 bytes（未知 text/* 子类型）
        raw = text
    except (UnicodeDecodeError, LookupError) as exc:
        defects.append(
            DefectInfo(part_path, type(exc).__name__, "warning",
                       f"按声明字符集解码失败：{exc.__class__.__name__}，尝试回退")
        )
        raw = part.get_payload(decode=True) or b""
    except Exception as exc:  # contentmanager 对极端畸形的输入可能抛 KeyError 等
        defects.append(
            DefectInfo(part_path, type(exc).__name__, "error",
                       f"正文解码异常：{exc.__class__.__name__}，尝试回退")
        )
        raw = part.get_payload(decode=True) or b""

    for candidate in (charset, "utf-8", "gb18030", "big5", "shift_jis", "iso-8859-1"):
        if not candidate:
            continue
        try:
            text = raw.decode(candidate)
            if candidate != charset and charset:
                defects.append(
                    DefectInfo(part_path, "CharsetFallback", "warning",
                              f"字符集 {charset!r} 解码失败，回退到 {candidate!r}")
                )
            return text, defects
        except (LookupError, UnicodeDecodeError):
            continue
    text = raw.decode("utf-8", errors="replace")
    defects.append(
        DefectInfo(part_path, "CharsetReplacement", "error",
                   "所有字符集回退失败，UTF-8 替换字符兜底，部分字符不可恢复")
    )
    return text, defects


def _raw_header(part: MIMEPart, wanted: str) -> str | None:
    """取未归一化的原始信头值（part.get() 会丢弃 RFC2231 扩展参数）。"""
    wanted = wanted.lower()
    for key, value in part.raw_items():
        if key.lower() == wanted:
            return value
    return None


def _safe_filename(part: MIMEPart) -> str | None:
    """提取附件名，优先 RFC2231 扩展参数 filename*（标准库会把它当重复参数丢弃）。

    手工解析原始 Content-Disposition：filename*=utf-8''%E6%8A%A5%E5%91%8A.pdf
    与 filename="fallback" 同时存在时，按 RFC 6266 采用扩展形式。
    """
    raw_cd = _raw_header(part, "Content-Disposition")
    if raw_cd:
        found = _extract_extended_filename(raw_cd)
        if found is not None:
            return found
    # Content-Type 中的 name* 同样处理
    raw_ct = _raw_header(part, "Content-Type")
    if raw_ct:
        found = _extract_extended_filename(raw_ct, param="name")
        if found is not None:
            return found
    try:
        return part.get_filename()
    except (LookupError, TypeError):
        return None


def _extract_extended_filename(header_value: str, *, param: str = "filename") -> str | None:
    import urllib.parse

    # 找到 param*= 形式（大小写不敏感），允许 charset'lang'url-encoding 结构
    match = re.search(
        rf"{re.escape(param)}\*\s*=\s*([^;]+)",
        header_value,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    token = match.group(1).strip().strip('"')
    if "'" in token:
        charset, _lang, percent = token.split("'", 2)
    else:
        charset, percent = "utf-8", token
    try:
        return urllib.parse.unquote(percent, encoding=charset or "utf-8", errors="replace")
    except LookupError:
        return urllib.parse.unquote(percent, encoding="utf-8", errors="replace")


def _content_id(part: MIMEPart) -> str | None:
    cid = part.get("Content-ID")
    if not cid:
        return None
    cid = cid.strip()
    if cid.startswith("<") and cid.endswith(">"):
        cid = cid[1:-1].strip()
    return cid or None


def _disposition(part: MIMEPart) -> str | None:
    try:
        return part.get_content_disposition()
    except Exception:
        raw = part.get("Content-Disposition", "")
        return raw.split(";")[0].strip().lower() or None if raw else None


def _is_real_multipart(part: MIMEPart) -> bool:
    """真正的多部件容器（multipart/*）。message/rfc822 虽 is_multipart() 为真但是封装附件。"""
    try:
        return part.get_content_maintype() == "multipart"
    except Exception:
        return False


def _classify(part: MIMEPart, maintype: str, subtype: str, disposition: str | None) -> str:
    if _is_real_multipart(part):
        return "multipart"
    is_text_body = maintype == "text" and subtype in {"plain", "html"}
    if disposition == "attachment":
        return "attachment"
    if disposition == "inline":
        if is_text_body and not _content_id(part):
            return "body"
        return "inline" if _content_id(part) else "attachment"
    if is_text_body:
        return "body"
    # multipart/related 里无 disposition 的图片等通常是内嵌资源
    if maintype in {"image", "audio", "video"} or subtype in {"rfc822", "partial"}:
        return "inline" if _content_id(part) else "attachment"
    return "other"


def _decode_attachment(part: MIMEPart) -> tuple[bytes | None, list[DefectInfo]]:
    defects: list[DefectInfo] = []
    cte = (part.get("Content-Transfer-Encoding") or "").strip().lower().replace("_", "-")
    maintype = ""
    try:
        maintype = part.get_content_maintype()
    except Exception:
        pass
    raw_payload = part.get_payload()

    # message/rfc822 等封装消息：get_payload(decode=True) 返回 None，
    # 需要把内层消息重新序列化为字节，保证转发附件不丢。
    if maintype == "message" and not isinstance(raw_payload, (str, bytes)):
        try:
            inner = part.get_content()
        except Exception as exc:
            defects.append(DefectInfo(
                "", "NestedMessageError", "error",
                f"封装消息无法读取：{exc.__class__.__name__}",
            ))
            return None, defects
        try:
            payload = bytes(inner)
        except Exception as exc:
            defects.append(DefectInfo(
                "", "NestedMessageError", "error",
                f"封装消息无法序列化：{exc.__class__.__name__}",
            ))
            return None, defects
        return payload, defects

    if isinstance(raw_payload, str):
        encoded_text = raw_payload
        if cte == "base64":
            import re as _re

            compact = "".join(encoded_text.split())
            if _re.search(r"[^A-Za-z0-9+/=]", compact):
                defects.append(DefectInfo(
                    "", "InvalidBase64CharactersDefect", "error",
                    "base64 载荷包含非法字符，标准库会忽略这些字符，数据可能不完整",
                ))
            core = compact.rstrip("=")
            if compact.count("=") > 2 or "=" in core or (core and len(core) % 4 == 1):
                defects.append(DefectInfo(
                    "", "InvalidBase64PaddingDefect", "error",
                    "base64 长度/填充非法，数据可能不完整",
                ))
        elif cte == "quoted-printable":
            import re as _re

            for line_no, line in enumerate(encoded_text.splitlines(), start=1):
                if _re.search(r"=(?![ \t]*\r?\n)(?![0-9A-Fa-f]{2})", line.rstrip("\r")):
                    defects.append(DefectInfo(
                        "", "InvalidQuotedPrintableDefect", "warning",
                        f"quoted-printable 第 {line_no} 行存在非法 = 转义",
                    ))
                    break
    try:
        payload = part.get_payload(decode=True)
    except Exception as exc:
        defects.append(
            DefectInfo("", "PayloadDecodeError", "error",
                       f"载荷传输解码失败：{exc.__class__.__name__}")
        )
        return None, defects
    if payload is None:
        defects.append(DefectInfo("", "EmptyPayload", "warning", "部件无载荷"))
        return b"", defects
    return payload, defects


def _safe_header_text(value: str) -> str:
    """raw_items() 对非法字节会使用 surrogateescape；恢复为可 JSON 序列化的文本。

    能还原为 UTF-8 的还原为原字符，不能还原的用 U+FFFD 替代，绝不伪造信头语义。
    """
    if not value:
        return value
    try:
        value.encode("utf-8")
        return value
    except UnicodeEncodeError:
        return value.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace")


def _build_tree(
    part: MIMEPart,
    part_path: str,
    ctx: "_ParseContext",
) -> PartInfo:
    defects = _defects_of(part, part_path)
    ctx.defects.extend(defects)

    maintype = "text"
    subtype = "plain"
    try:
        maintype, subtype = part.get_content_type().split("/", 1)
    except (ValueError, AttributeError):
        pass
    content_type = f"{maintype}/{subtype}"
    disposition = _disposition(part)
    filename = _safe_filename(part)
    cid = _content_id(part)
    charset = _content_charset(part)
    role = _classify(part, maintype, subtype, disposition)

    boundary = None
    real_mp = _is_real_multipart(part)
    if real_mp:
        try:
            boundary = part.get_boundary()
        except Exception:
            boundary = None

    node = PartInfo(
        part_path=part_path,
        content_type=content_type,
        disposition=disposition,
        filename=filename,
        content_id=cid,
        content_location=part.get("Content-Location"),
        charset=charset,
        is_multipart=real_mp,
        multipart_boundary=boundary,
        size=0,
        role=role,
    )

    if real_mp:
        for index, child in enumerate(part.iter_parts(), start=1):
            child_path = f"{part_path}.{index}" if part_path else str(index)
            node.children.append(_build_tree(child, child_path, ctx))
        # multipart 预amble/epilogue 丢失也算结构异常线索
        if part.get_content_maintype() == "multipart" and not node.children:
            ctx.defects.append(
                DefectInfo(part_path, "EmptyMultipart", "error",
                           "multipart 部件没有任何子部件（可能是边界损坏）")
            )
        return node

    # 叶子部件
    if role == "body" and content_type == "text/plain" and ctx.text_part is None:
        text, d = _decode_text(part, part_path, charset)
        ctx.defects.extend(d)
        ctx.text_part = (part_path, text)
    elif role == "body" and content_type == "text/html" and ctx.html_part is None:
        text, d = _decode_text(part, part_path, charset)
        ctx.defects.extend(d)
        ctx.html_part = (part_path, text)
    elif role in {"attachment", "inline"} or filename is not None:
        payload, d = _decode_attachment(part)
        for each in d:
            each.part_path = part_path
        ctx.defects.extend(d)
        if payload is not None:
            kind = "inline" if role == "inline" or (disposition == "inline" and cid) else "attachment"
            ctx.attachments.append(
                AttachmentPayload(
                    filename=filename,
                    payload=payload,
                    content_type=content_type,
                    content_id=cid,
                    content_location=part.get("Content-Location"),
                    disposition=disposition,
                    kind=kind,
                    size=len(payload),
                    part_path=part_path,
                )
            )
            node.size = len(payload)
    elif role == "body":
        # text/* 非 plain/html 的正文，保底按文本解码
        text, d = _decode_text(part, part_path, charset)
        ctx.defects.extend(d)
        if ctx.text_part is None:
            ctx.text_part = (part_path, text)
    else:
        # 其它二进制叶子（other）：默认作为附件保存，避免数据丢失
        payload, d = _decode_attachment(part)
        for each in d:
            each.part_path = part_path
        ctx.defects.extend(d)
        if payload is not None and payload:
            ctx.attachments.append(
                AttachmentPayload(
                    filename=filename,
                    payload=payload,
                    content_type=content_type,
                    content_id=cid,
                    content_location=part.get("Content-Location"),
                    disposition=disposition,
                    kind="attachment",
                    size=len(payload),
                    part_path=part_path,
                )
            )
            node.size = len(payload)

    return node


class _ParseContext:
    def __init__(self) -> None:
        self.defects: list[DefectInfo] = []
        self.attachments: list[AttachmentPayload] = []
        self.text_part: tuple[str, str] | None = None
        self.html_part: tuple[str, str] | None = None


def _address_list(msg: EmailMessage, name: str) -> list[Address]:
    header = msg.get(name)
    if isinstance(header, str):
        addrs = parse_addresses_raw(header)
    else:
        addrs = parse_address_header(header)
    for a in addrs:
        a.name = _safe_header_text(a.name)
        a.address = _safe_header_text(a.address)
    return addrs


def parse_eml(raw: bytes) -> ParsedMessage:
    """把 EML 原始字节解析为 ParsedMessage。致命损坏抛 FatalParseError。"""
    if not isinstance(raw, (bytes, bytearray)):
        raise FatalParseError("输入必须是原始字节", stage="input")
    raw = bytes(raw)
    if not raw.strip():
        raise FatalParseError("EML 内容为空", stage="input")

    sha = hashlib.sha256(raw).hexdigest()
    try:
        msg = BytesParser(policy=default_policy).parsebytes(raw)
    except Exception as exc:
        raise FatalParseError(f"RFC822 解析失败: {exc.__class__.__name__}", stage="rfc822") from exc
    if not isinstance(msg, EmailMessage):
        raise FatalParseError("顶层不是 email message", stage="rfc822")
    # 完全没有信头（只有一堆正文/二进制）说明不是可归档的 RFC822 邮件
    if not list(msg.raw_items()):
        raise FatalParseError("输入不包含任何信头，不是有效的 RFC822 邮件", stage="headers")

    ctx = _ParseContext()
    tree = _build_tree(msg, "", ctx)

    # 信头 ----------------------------------------------------------------
    mid_raw_value = msg.get("Message-ID")
    message_id, message_id_raw, mid_defects = parse_message_id(mid_raw_value, "")
    ctx.defects.extend(mid_defects)

    in_reply = parse_in_reply_to(msg.get("In-Reply-To"))
    refs = parse_references(msg.get("References"))
    if in_reply.multiple:
        ctx.defects.append(
            DefectInfo("", "MultipleInReplyTo", "warning",
                       "In-Reply-To 包含多个标识，全部保留为边，不猜测主父"))
    edges: list[ReferenceEdge] = []
    ordinal = 0
    if in_reply.ids:
        for raw_id in in_reply.ids:
            edges.append(ReferenceEdge("in-reply-to", raw_id, ordinal,
                                       f"<{raw_id}>" if raw_id else None))
            ordinal += 1
    for idx, raw_id in enumerate(refs.ids):
        edges.append(ReferenceEdge("references", raw_id, idx, refs.raw_ids[idx] if idx < len(refs.raw_ids) else None))

    date_iso, date_defects = parse_date(msg.get("Date"), "")
    ctx.defects.extend(date_defects)

    subject_raw = msg.get("Subject")
    subject_raw_safe = _safe_header_text(subject_raw) if subject_raw is not None else subject_raw
    subject_decoded = decode_header_value(subject_raw_safe)

    headers_raw = iter_raw_headers(msg)
    headers_safe = [(name, _safe_header_text(value)) for name, value in headers_raw]
    header_summary = [
        {"name": name, "value": decode_header_value(value) if name.lower() in {"subject", "comments", "keywords"} else value}
        for name, value in headers_safe
    ]

    text_path, body_text = ctx.text_part if ctx.text_part else (None, "")
    html_path, html_raw = ctx.html_part if ctx.html_part else (None, "")
    sanitized = sanitize_html(html_raw) if html_raw else None

    has_errors = any(d.severity == "error" for d in ctx.defects)

    return ParsedMessage(
        raw_sha256=sha,
        raw_size=len(raw),
        message_id=message_id,
        message_id_raw=_safe_header_text(message_id_raw) if message_id_raw is not None else None,
        date_iso=date_iso,
        subject_decoded=subject_decoded,
        subject_raw=subject_raw_safe,
        from_=_address_list(msg, "From"),
        to=_address_list(msg, "To"),
        cc=_address_list(msg, "Cc"),
        bcc=_address_list(msg, "Bcc"),
        sender=_address_list(msg, "Sender"),
        reply_to=_address_list(msg, "Reply-To"),
        body_text=body_text,
        body_html_sanitized=sanitized.sanitized if sanitized else "",
        body_html_escaped=sanitized.escaped if sanitized else "",
        body_part_path_text=text_path,
        body_part_path_html=html_path,
        parts=tree,
        attachments=ctx.attachments,
        headers=[
            {"name": name, "raw_value": value} for name, value in headers_safe
        ],
        header_summary=header_summary,
        references=edges,
        defects=ctx.defects,
        has_errors=has_errors,
    )
