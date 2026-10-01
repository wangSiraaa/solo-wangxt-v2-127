"""解析器、清洗器、会话图、受控文件存储的单元测试。"""
from __future__ import annotations

import os
import pytest

from app.parsing import parse_eml, rebuild_threads, sanitize_html, subject_weak_key
from app.parsing.threads import weak_subject_candidates
from app.storage.filestore import (
    FileStore,
    PathTraversalError,
    sanitize_filename,
)


# ---------------------------------------------------------------------------
# 清洗器攻击面
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "html,bad",
    [
        ("<script>alert(1)</script>ok", "alert(1)"),
        ("<img src=x onerror=alert(1)>", "onerror"),
        ("<svg/onload=alert(1)>", "onload"),
        ("<iframe src='http://evil'></iframe>", "iframe"),
        ("<a href=\"javascript:alert(1)\">x</a>", "javascript"),
        ("<a href=\" data:text/html,<script>\">x</a>", "data:text"),
        ("<a href=\"vbscript:msgbox\">x</a>", "vbscript"),
        ("<link rel=import href=http://evil>", "<link"),
        ("<meta http-equiv=refresh content='0;url=http://evil'>", "http-equiv"),
        ("<base href='http://evil/'>", "<base"),
        ("<object data='http://evil/x.swf'></object>", "object"),
        ("<embed src='http://evil/x.swf'>", "embed"),
        ("<form action='http://evil'><button>x</button></form>", "form"),
        ("<img src='http://evil/tracker.png'>", "http://evil"),
        ("<img src='https://evil/tracker.png'>", "evil"),
        ("<img src='//evil/tracker.png'>", "evil"),
        ("<div style=\"background:url(http://evil)\">x</div>", "background:url"),
        ("<!-- <script>alert(1)</script> -->", "alert"),
        ("<p style=expression(alert(1))>x</p>", "expression"),
        ("<ScRiPt>alert(1)</ScRiPt>", "alert"),
        ("<a href='JaVaScRiPt:alert(1)'>x</a>", "JaVaScRiPt:alert"),
    ],
)
def test_sanitizer_blocks(html, bad):
    out = sanitize_html(html).sanitized
    assert bad not in out, (html, out)


def test_sanitizer_keeps_safe_and_cid():
    src = """
    <p>hello 中文</p>
    <a href="https://ok.example/a?b=1#c" rel="x">link</a>
    <a href="mailto:a@b.com">mail</a>
    <img src="cid:part1234@mail" alt="x">
    <h1><b>标题</b></h1>
    """
    out = sanitize_html(src).sanitized
    assert "https://ok.example/a?b=1#c" in out
    assert "mailto:a@b.com" in out
    assert "cid:part1234@mail" in out
    assert "hello 中文" in out
    assert "<h1>" in out
    # a 标签自动补 noopener
    assert "noopener" in out


def test_sanitizer_malformed_does_not_crash():
    cases = [
        "<", "<<<", "><><>", "<a", "<a href>",
        "a" * 10000, "<img src=x" + " onerror" * 100,
        "\x00\x01<a href='\xff'>",
        "</div></span>text",
        "<table><tr><td>x",
    ]
    for src in cases:
        r = sanitize_html(src)
        assert r.sanitized  # 非 script 截断场景总有输出
    # 未闭合 script：剩余内容被吞是 HTML5 正确行为，但不能抛异常
    r = sanitize_html("<script><script>")
    assert r.sanitized == ""
    # 关键：文档被截断后前面的正常内容与闭合的 script 不受影响
    r2 = sanitize_html("<p>a</p><script>bad</script><p>b</p><script>unterminated")
    assert "<p>a</p>" in r2.sanitized
    assert "<p>b</p>" in r2.sanitized
    assert "bad" not in r2.sanitized


def test_sanitizer_nested_dropped_void():
    # link 在 head 中，不能吞掉 body 内容（回归用例）
    src = "<html><head><link rel=stylesheet href=http://x></head><body><p>保留</p></body></html>"
    out = sanitize_html(src).sanitized
    assert "<link" not in out.lower()
    assert "保留" in out


def test_escaped_version_is_full_escape():
    src = "<p onclick='x'>hi</p>"
    r = sanitize_html(src)
    assert r.escaped == "&lt;p onclick=&#x27;x&#x27;&gt;hi&lt;/p&gt;"
    assert "<p onclick" in r.sanitized.lower() is False or "onclick" not in r.sanitized


# ---------------------------------------------------------------------------
# 文件名无害化
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,safe",
    [
        ("../../../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system32\\x.dll", "x.dll"),
        ("a/b/c.pdf", "c.pdf"),
        ("normal.report.final.pdf", "normal.report.final.pdf"),
        ("报告 (1).pdf", "报告 (1).pdf"),
        ("x\x00y.txt", "xy.txt"),
        ("CON.pdf", "CON.pdf"),
        ("weird:name?.pdf", "weird_name.pdf"),
        ("trailing dot.pdf.", "trailing dot.pdf"),
    ],
)
def test_sanitize_filename(raw, safe):
    out = sanitize_filename(raw, "application/pdf")
    assert "/" not in out and "\\" not in out and ".." not in out
    assert out == safe


@pytest.mark.parametrize(
    "raw,ct,safe",
    [
        ("", "application/pdf", "unnamed.pdf"),
        ("....", "application/pdf", "unnamed.pdf"),
        (".hidden", "application/pdf", "unnamed.pdf"),
        ("...", "image/png", "unnamed.png"),
        ("...", None, "unnamed.bin"),
        ("x.pdf", None, "x.pdf"),
    ],
)
def test_sanitize_filename_empty(raw, ct, safe):
    assert sanitize_filename(raw, ct) == safe


# ---------------------------------------------------------------------------
# 受控目录：路径越界
# ---------------------------------------------------------------------------

def test_filestore_blocks_traversal(tmp_path):
    fs = FileStore(tmp_path / "root")
    with pytest.raises(PathTraversalError):
        fs._resolve_inside(fs.root, "attachments", "..", "..", "etc", "x")
    with pytest.raises(PathTraversalError):
        fs.open_blob("../../../../etc/passwd")
    with pytest.raises(PathTraversalError):
        fs.open_blob("attachments/../../etc/passwd")
    # 绝对路径注入也逃不出去
    with pytest.raises(PathTraversalError):
        fs.open_blob("/etc/passwd")


def test_filestore_symlink_escape_blocked(tmp_path):
    root = tmp_path / "root"
    fs = FileStore(root)
    # 在受控目录里放一个指向外部的符号链接
    outside = tmp_path / "secret.bin"
    outside.write_bytes(b"secret")
    link = root / "attachments" / "aa"
    link.mkdir(parents=True)
    os.symlink(outside, link / "link.bin")
    with pytest.raises(PathTraversalError):
        fs.open_blob("attachments/aa/link.bin")


def test_filestore_content_addressing_and_dedup(tmp_path):
    fs = FileStore(tmp_path / "root")
    data = b"hello attachment" * 100
    import hashlib

    sha = hashlib.sha256(data).hexdigest()
    b1 = fs.store_attachment(data, sha, ".bin")
    b2 = fs.store_attachment(data, sha, ".bin")
    assert b1.path == b2.path
    assert b1.reused is False and b2.reused is True
    path, size = fs.open_blob(b1.path)
    assert path.read_bytes() == data
    assert size == len(data)


# ---------------------------------------------------------------------------
# 会话图：循环 / 自引用 / 悬挂 / 主题弱键
# ---------------------------------------------------------------------------

def test_thread_chain_and_branch():
    nodes = ["a", "b", "c", "d"]
    edges = [("b", "a"), ("c", "b"), ("d", "a")]
    r = rebuild_threads(nodes, edges)
    assert len(r.threads) == 1
    assert r.cycles == []


def test_thread_cycle_terminates():
    nodes = ["a", "b", "c"]
    edges = [("a", "c"), ("b", "a"), ("c", "b")]  # A->C->B->A 环
    r = rebuild_threads(nodes, edges)
    assert len(r.threads) == 1
    assert r.cycles, "必须检出环"
    assert all(n in r.members for n in "abc")


def test_thread_self_reference():
    r = rebuild_threads(["a"], [("a", "a")])
    assert ["a"] in r.cycles
    assert r.self_references == ["a"]


def test_thread_dangling_and_disconnected():
    nodes = ["a", "z"]
    edges = [("a", "missing-parent@x")]
    r = rebuild_threads(nodes, edges)
    assert any(d["target"] == "missing-parent@x" for d in r.dangling)
    # a 与 z 都没有真实邻居，都不分配会话
    assert "a" not in r.members
    assert "z" not in r.members
    assert r.threads == []


def test_thread_large_cycle_no_hang():
    # 5000 节点大环，验证有界终止
    n = 5000
    nodes = [f"m{i}" for i in range(n)]
    edges = [(f"m{i}", f"m{(i + 1) % n}") for i in range(n)]
    r = rebuild_threads(nodes, edges)
    assert len(r.threads) == 1
    assert r.cycles


def test_subject_weak_key_strips_prefixes():
    assert subject_weak_key("Re: 季度报告") == "季度报告"
    assert subject_weak_key("Fwd: RE: 季度报告") == "季度报告"
    assert subject_weak_key("  AW:  [2] 季度报告") == "季度报告"
    assert subject_weak_key("Re:Re:Re:x") == "x"


def test_weak_candidates_never_merge():
    data = [("e1", "Re: 同主题"), ("e2", "Fwd: 同主题"), ("e3", "不同")]
    cands = weak_subject_candidates(data)
    assert len(cands) == 1
    assert set(cands[0]["email_ids"]) == {"e1", "e2"}


# ---------------------------------------------------------------------------
# 解析器边界
# ---------------------------------------------------------------------------

def test_parse_deep_nesting():
    # 手工构造 100 层嵌套 multipart
    inner = ("Content-Type: text/plain; charset=utf-8\r\n\r\n深层正文 deep\r\n")
    cur = inner
    for i in range(100):
        b = f"B{i:03d}"
        cur = f'Content-Type: multipart/mixed; boundary="{b}"\r\n\r\n--{b}\r\n{cur}--{b}--\r\n'
    raw = (
        "From: a@x.com\r\nTo: b@x.com\r\nSubject: deep\r\n"
        "Message-ID: <deep@x>\r\n" + cur
    ).encode()
    m = parse_eml(raw)
    assert "深层正文" in m.body_text
    assert m.parts.is_multipart


def test_parse_nested_message_rfc822():
    from email.message import EmailMessage

    inner = EmailMessage()
    inner["From"] = "inner@x.com"
    inner["Subject"] = "内层信"
    inner["Message-ID"] = "<inner@x>"
    inner.set_content("inner body")

    outer = EmailMessage()
    outer["From"] = "outer@x.com"
    outer["Message-ID"] = "<outer@x>"
    outer["Subject"] = "外层"
    outer.make_related()
    outer.add_attachment(inner)
    m = parse_eml(bytes(outer))
    # message/rfc822 被当作附件/内嵌保留
    assert any(a.content_type in ("message/rfc822",) for a in m.attachments)


def test_parse_multiple_in_reply_to_retained():
    raw = (
        "From: a@x.com\r\nMessage-ID: <multi-irt@x>\r\n"
        "In-Reply-To: <p1@x> <p2@x>\r\n\r\nbody\r\n"
    ).encode()
    m = parse_eml(raw)
    irt = [e for e in m.references if e.kind == "in-reply-to"]
    assert {e.target_message_id for e in irt} == {"p1@x", "p2@x"}
    assert any(d.defect_type == "MultipleInReplyTo" for d in m.defects)


def test_parse_bare_message_id_normalized():
    raw = b"From: a@x.com\r\nMessage-ID: bare-id-without-brackets@x\r\n\r\nx\r\n"
    m = parse_eml(raw)
    assert m.message_id == "bare-id-without-brackets@x"
