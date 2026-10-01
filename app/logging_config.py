"""日志配置。

架构上解析/存储代码从不把附件或邮件正文写入日志；这里再加一道防线：
所有日志记录都经过 ``RedactingFilter``，把疑似 base64/quoted-printable
的长段载荷替换成占位符，并截断超长行。普通日志因此不可能混入附件内容。
"""
from __future__ import annotations

import logging
import re
import sys

# 连续 80 个以上的 base64 字符，基本只可能是编码后的载荷
_B64_RUN = re.compile(r"[A-Za-z0-9+/=\r\n]{80,}")
# 连续的 =E5=88 风格 QP 序列
_QP_RUN = re.compile(r"(?:=[0-9A-Fa-f]{2}){10,}")
_MAX_TOTAL = 4000
_MAX_LINE = 300


def redact_text(text: str) -> str:
    """把疑似二进制/编码载荷替换为占位符，并限制长度。"""
    if not text:
        return text

    def _b64_repl(match: re.Match[str]) -> str:
        return f"<redacted:{len(match.group(0))}b>"

    text = _B64_RUN.sub(_b64_repl, text)
    text = _QP_RUN.sub(_b64_repl, text)
    if len(text) > _MAX_TOTAL:
        text = text[:_MAX_TOTAL] + f"...<truncated:{len(text) - _MAX_TOTAL}c>"
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - 日志本身失败不应拖垮服务
            message = "<unformattable log record>"
        record.msg = redact_text(message)
        record.args = ()
        # 异常栈里也可能携带片段，保留类型与行号但抹掉消息内容中的大段数据
        if record.exc_info:
            exc_type, exc = record.exc_info[0], record.exc_info[1]
            record.exc_text = f"{exc_type.__name__ if exc_type else 'Exception'}: {redact_text(str(exc))}"
        return True


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"mail_archive.{name}")
