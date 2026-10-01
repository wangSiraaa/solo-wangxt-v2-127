"""HTML 安全清洗，仅依赖标准库 ``html.parser``。

策略（默认安全）：
* 标签白名单；script/style/iframe/object/embed/svg/link/meta/base/form 等一律移除；
* 未知标签不删除其文本，而是把标签本身转义为 &lt;...&gt;，内容保留；
* 属性白名单；所有 on* 事件属性、style、srcset 一律删除；
* 远程资源全部拦截：img 仅允许 cid:（指向同封邮件的内嵌资源），
  a[href] 仅允许 http/https/mailto，javascript:/data:/vbscript: 等一律清除；
* 注释、处理指令、DOCTYPE 声明一律丢弃；
* 同时返回一份完全转义版本（body_html_escaped），供“只存不执行”的场景使用。

本模块不做美化、不抓取网络、不解析 CSS。
"""
from __future__ import annotations

import html as _html
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

# 允许出现的标签及其允许的属性（通用属性另算）
_ALLOWED_TAGS: dict[str, set[str]] = {
    "a": {"href"},
    "abbr": set(),
    "acronym": set(),
    "address": set(),
    "article": set(),
    "aside": set(),
    "b": set(),
    "bdi": set(),
    "bdo": {"dir"},
    "blockquote": {"cite"},
    "br": set(),
    "caption": set(),
    "cite": set(),
    "code": set(),
    "col": {"span"},
    "colgroup": {"span"},
    "dd": set(),
    "del": {"cite", "datetime"},
    "details": {"open"},
    "dfn": set(),
    "div": set(),
    "dl": set(),
    "dt": set(),
    "em": set(),
    "figcaption": set(),
    "figure": set(),
    "h1": set(),
    "h2": set(),
    "h3": set(),
    "h4": set(),
    "h5": set(),
    "h6": set(),
    "header": set(),
    "hr": set(),
    "i": set(),
    "img": {"alt", "src"},
    "ins": {"cite", "datetime"},
    "kbd": set(),
    "li": {"value"},
    "mark": set(),
    "nav": set(),
    "ol": {"start", "type"},
    "p": set(),
    "pre": set(),
    "q": {"cite"},
    "s": set(),
    "samp": set(),
    "section": set(),
    "small": set(),
    "span": set(),
    "strong": set(),
    "sub": set(),
    "sup": set(),
    "table": {"border"},
    "tbody": set(),
    "td": {"colspan", "rowspan", "headers"},
    "tfoot": set(),
    "th": {"colspan", "rowspan", "headers", "scope"},
    "thead": set(),
    "time": {"datetime"},
    "tr": set(),
    "u": set(),
    "ul": {"type"},
    "var": set(),
}

# 无论标签是否允许，这些属性一律删除
_FORBIDDEN_ATTR_PREFIXES = ("on",)
_FORBIDDEN_ATTRS = {"style", "srcset", "background", "poster", "classid", "codebase", "data"}
_VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}
# 明确会执行脚本/加载远程资源/改变文档基址的标签
_DROPPED_TAGS = {
    "script", "style", "iframe", "frame", "frameset", "object", "embed",
    "applet", "link", "meta", "base", "noscript", "template", "svg",
    "math", "form", "input", "button", "textarea", "select", "option",
    "optgroup", "label", "fieldset", "output", "progress", "meter",
    "canvas", "audio", "video", "source", "track", "param", "title",
}
# 只丢弃标签本身、内部文本仍保留（html/head/body 只是结构包裹；title 在文档片段里无害）
_DROP_TAG_ONLY = {"head", "html", "body"}
_SAFE_HREF_SCHEMES = {"http", "https", "mailto"}
_SAFE_IMG_SCHEMES = {"cid"}


# script/style 是 HTML5 rawtext 元素：内部不解析标签，遇到第一个
# 同名结束标签即关闭（嵌套的 <script> 不算新层级）
_RAWTEXT_TAGS = {"script", "style"}


@dataclass
class SanitizeResult:
    sanitized: str
    escaped: str
    dropped_tags: int = 0
    unknown_tags: int = 0
    stripped_attributes: int = 0
    dropped_elements: list[str] = field(default_factory=list)


def _scheme_of(url: str) -> str:
    try:
        return urlsplit(url.strip()).scheme.lower()
    except ValueError:
        return ""


def _safe_href(value: str) -> bool:
    v = value.strip()
    if not v:
        return False
    scheme = _scheme_of(v)
    if scheme == "":
        return False  # 没有基址上下文，相对链接不可判定，拒绝
    return scheme in _SAFE_HREF_SCHEMES


def _safe_img_src(value: str) -> bool:
    v = value.strip()
    if not v:
        return False
    scheme = _scheme_of(v)
    # cid: 指向同一封邮件的内嵌资源（Content-ID），不产生网络访问
    return scheme in _SAFE_IMG_SCHEMES and bool(unquote(v[4:]).strip())


class _SanitizingParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.out: list[str] = []
        self.result = SanitizeResult(sanitized="", escaped="")
        # 被整段丢弃的标签栈（iframe/object 等内部文本也要丢弃）
        self._suppress_depth = 0
        self._suppress_tags: list[str] = []
        # script/style 的 rawtext 模式（标准库 CDATA 模式），内部文本一律不输出
        self._cdata_tag: str | None = None

    # -- 工具 ------------------------------------------------------------
    def _emit_text(self, data: str) -> None:
        self.out.append(_html.escape(data, quote=False))

    # -- HTMLParser 回调 -------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        if tag_l in _DROP_TAG_ONLY:
            self.result.dropped_tags += 1
            if len(self.result.dropped_elements) < 50:
                self.result.dropped_elements.append(tag_l)
            return
        if tag_l in _DROPPED_TAGS:
            self.result.dropped_tags += 1
            if len(self.result.dropped_elements) < 50:
                self.result.dropped_elements.append(tag_l)
            # script/style 进入标准库的 rawtext/CDATA 模式：
            # 内部不解析任何标签，首个同名 </tag> 自动结束（嵌套 <script> 不算层级），
            # 文档截断时模式维持到 EOF，符合 HTML5。
            if tag_l in _RAWTEXT_TAGS:
                self.set_cdata_mode(tag_l)
                self._cdata_tag = tag_l
                return
            # link/meta/base 等空元素没有结束标签，只丢弃标签本身，不压栈
            if tag_l not in _VOID_ELEMENTS:
                self._suppress_depth += 1
                self._suppress_tags.append(tag_l)
            return
        if self._suppress_depth:
            # 在被丢弃元素内部，所有内容一并吞掉
            return
        if tag_l not in _ALLOWED_TAGS:
            # 未知标签：转义标签本身，保留内部文本
            self.result.unknown_tags += 1
            self.out.append("&lt;" + _html.escape(tag, quote=True))
            for k, v in attrs:
                self.result.stripped_attributes += 1
                if v is None:
                    self.out.append(" " + _html.escape(k, quote=True))
                else:
                    self.out.append(" " + _html.escape(f'{k}="{v}"', quote=True))
            self.out.append("&gt;")
            return
        safe_attrs = self._filter_attrs(tag_l, attrs)
        if tag_l == "a" and safe_attrs:
            safe_attrs.append(("rel", "noopener noreferrer"))
        rendered = tag_l
        for k, v in safe_attrs:
            rendered += f' {k}="{_html.escape(v, quote=True)}"'
        if tag_l in _VOID_ELEMENTS:
            self.out.append(f"<{rendered}>")
        else:
            self.out.append(f"<{rendered}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        if tag_l in _DROP_TAG_ONLY:
            return
        if tag_l in _DROPPED_TAGS:
            self.result.dropped_tags += 1
            if len(self.result.dropped_elements) < 50:
                self.result.dropped_elements.append(tag_l)
            return
        if self._suppress_depth:
            return
        if tag_l not in _ALLOWED_TAGS:
            self.result.unknown_tags += 1
            self.out.append("&lt;" + _html.escape(tag, quote=True) + "/&gt;")
            for k, v in attrs:
                self.result.stripped_attributes += 1
            return
        safe_attrs = self._filter_attrs(tag_l, attrs)
        if tag_l == "a" and safe_attrs:
            safe_attrs.append(("rel", "noopener noreferrer"))
        rendered = tag_l
        for k, v in safe_attrs:
            rendered += f' {k}="{_html.escape(v, quote=True)}"'
        self.out.append(f"<{rendered}>")

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        if self._cdata_tag == tag_l:
            # 标准库此刻已退出 CDATA 模式
            self._cdata_tag = None
            return
        if tag_l in _DROP_TAG_ONLY:
            return
        if self._suppress_depth:
            if tag_l in self._suppress_tags:
                # 弹出最近一个同名丢弃标签（容忍畸形嵌套）
                for idx in range(len(self._suppress_tags) - 1, -1, -1):
                    if self._suppress_tags[idx] == tag_l:
                        del self._suppress_tags[idx:]
                        self._suppress_depth = len(self._suppress_tags)
                        break
            return
        if tag_l in _DROPPED_TAGS:
            return
        if tag_l not in _ALLOWED_TAGS:
            self.out.append("&lt;/" + _html.escape(tag, quote=True) + "&gt;")
            return
        if tag_l in _VOID_ELEMENTS:
            return
        self.out.append(f"</{tag_l}>")

    def handle_data(self, data: str) -> None:
        if self._suppress_depth or self._cdata_tag:
            return
        self._emit_text(data)

    def handle_entityref(self, name: str) -> None:
        if self._suppress_depth:
            return
        # html.entities 解码后再转义，杜绝把实体当作注入载体
        import html.entities

        ch = html.entities.html5.get(name + ";") or html.entities.entitydefs.get(name)
        text = ch if isinstance(ch, str) else f"&{name};"
        self._emit_text(text)

    def handle_charref(self, name: str) -> None:
        if self._suppress_depth:
            return
        try:
            if name.startswith(("x", "X")):
                codepoint = int(name[1:], 16)
            else:
                codepoint = int(name, 10)
            text = chr(codepoint)
        except (ValueError, OverflowError):
            text = f"&#{name};"
        self._emit_text(text)

    def handle_comment(self, data: str) -> None:
        # 注释一律不保留（条件注释曾被用于绕过过滤）
        return

    def handle_decl(self, decl: str) -> None:
        return

    def unknown_decl(self, data: str) -> None:
        return

    def handle_pi(self, data: str) -> None:
        return

    # -- 属性过滤 --------------------------------------------------------
    def _filter_attrs(self, tag: str, attrs: list[tuple[str, str | None]]) -> list[tuple[str, str]]:
        allowed = _ALLOWED_TAGS.get(tag, set())
        out: list[tuple[str, str]] = []
        for key, value in attrs:
            k = key.lower()
            if value is None:
                self.result.stripped_attributes += 1
                continue
            if k in _FORBIDDEN_ATTRS or k.startswith(_FORBIDDEN_ATTR_PREFIXES):
                self.result.stripped_attributes += 1
                continue
            if k not in allowed and k not in {"alt", "title", "colspan", "rowspan", "datetime"}:
                self.result.stripped_attributes += 1
                continue
            if k == "href":
                if not _safe_href(value):
                    self.result.stripped_attributes += 1
                    continue
            elif k == "src":
                if not _safe_img_src(value):
                    self.result.stripped_attributes += 1
                    continue
            elif k in {"cite"}:
                if not _safe_href(value):
                    self.result.stripped_attributes += 1
                    continue
            out.append((k, value))
        return out


def sanitize_html(raw_html: str) -> SanitizeResult:
    """清洗 HTML。永远不抛异常：解析器本身遇到坏输入也只产生转义文本。"""
    parser = _SanitizingParser()
    try:
        parser.feed(raw_html or "")
        parser.close()
    except Exception:
        # 清洗器自身失败时退回完全转义（最保守、仍满足“只存不执行”）
        return SanitizeResult(
            sanitized=_html.escape(raw_html or "", quote=True),
            escaped=_html.escape(raw_html or "", quote=True),
        )
    sanitized = "".join(parser.out)
    parser.result.sanitized = sanitized
    parser.result.escaped = _html.escape(raw_html or "", quote=True)
    return parser.result
