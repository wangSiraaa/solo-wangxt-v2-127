"""会话（thread）计算。

硬规则：仅以 Message-ID / In-Reply-To / References 建边。
主题相同**只产生弱候选**，绝不参与自动合并。
循环引用（A->B->A、自引用）不能让遍历死循环，也不强行拆开正常链路，
而是在结果里把环标记出来保留冲突。
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

_PREFIX_RE = re.compile(
    r"^\s*(?:re|sv|aw|wg|fwd?|fw|tr|res|rif|antw|odp|va)\s*"
    r"(?:\[\d+\]|\(\d+\))?\s*[:：]\s*(?:\[\d+\]|\(\d+\))?\s*",
    re.IGNORECASE,
)
_SQUASH_RE = re.compile(r"\s+")


@dataclass
class ThreadNode:
    message_id: str
    email_id: str | None = None
    ordinal: int = 0
    cycle: bool = False


@dataclass
class ThreadResult:
    threads: list[list[str]] = field(default_factory=list)  # 每簇的 message_id 列表
    members: dict[str, str] = field(default_factory=dict)    # message_id -> thread_id
    thread_ids: dict[str, str] = field(default_factory=dict) # 代表元 -> thread_id
    cycles: list[list[str]] = field(default_factory=list)    # 检测到的环（有序路径）
    dangling: list[dict[str, str | int]] = field(default_factory=list)  # 指向不存在邮件的边
    self_references: list[str] = field(default_factory=list)


def subject_weak_key(subject: str | None) -> str:
    """主题弱键：去掉 Re/Fwd 等转发前缀与多余空白，仅用于候选提示。"""
    if not subject:
        return ""
    s = subject
    # 反复剥离，处理 "Re: Fwd: Re: x" 这类叠加前缀
    while True:
        new = _PREFIX_RE.sub("", s, count=1)
        if new == s:
            break
        s = new
    s = _SQUASH_RE.sub(" ", s).strip().lower()
    return s


def weak_subject_candidates(subjects: list[tuple[str, str]]) -> list[dict[str, list[str]]]:
    """输入 [(email_id, subject), ...]，返回同弱键分组（每组 >=2）。

    仅作为候选暴露给 API，调用方不得据此合并 thread。
    """
    groups: dict[str, list[str]] = defaultdict(list)
    for email_id, subject in subjects:
        key = subject_weak_key(subject)
        if len(key) >= 2:  # 过短的主题没有区分度
            groups[key].append(email_id)
    return [
        {"subject_key": key, "email_ids": ids}
        for key, ids in groups.items()
        if len(ids) > 1
    ]


def rebuild_threads(
    nodes: list[str],
    edges: list[tuple[str, str]],
) -> ThreadResult:
    """并查集聚类 + 环检测。

    nodes: 存在的 Message-ID 集合；
    edges: (src_message_id, target_message_id)，src 可能为 None（仅 References 链中的邮件本身缺失）。
    实现保证对任意环图终止（visited 上界），且复杂度近似 O(N·α)。
    """
    result = ThreadResult()
    node_set = set(nodes)

    parent: dict[str, str] = {n: n for n in nodes}

    def find(x: str) -> str:
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:  # 路径压缩
            parent[x], x = root, parent[x]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # 邻接表用于环检测（只在存在的节点之间）。
    # 自环单独记录（set 无法区分自边数量），并保证该节点至少形成一个会话。
    adjacency: dict[str, set[str]] = defaultdict(set)
    self_loops: dict[str, int] = defaultdict(int)
    for src, dst in edges:
        if src is not None and src == dst:
            result.self_references.append(src)
            self_loops[src] += 1
        if src is not None and src in node_set and dst in node_set:
            if src != dst:
                adjacency[src].add(dst)
                adjacency[dst].add(src)  # 无向边用于聚类与成环判定
            union(src, dst)
        elif src is not None and src in node_set and dst not in node_set:
            result.dangling.append({"src": src, "target": dst, "kind": "missing-target"})
        elif src is None or src not in node_set:
            # 边的起点都缺失：无法聚类，记录悬挂引用
            result.dangling.append({"src": src or "", "target": dst, "kind": "missing-source"})

    # 环检测：对每个无向连通分量，|E| > |V| 即含环；再用 DFS 找出具体环
    seen_global: set[str] = set()
    for start in nodes:
        if start in seen_global:
            continue
        # 收集分量
        component: list[str] = []
        stack = [start]
        seen_global.add(start)
        while stack:
            cur = stack.pop()
            component.append(cur)
            for nxt in adjacency.get(cur, ()):
                if nxt not in seen_global:
                    seen_global.add(nxt)
                    stack.append(nxt)
        # 只有真实边（无向邻接或自环）才形成会话；仅悬挂引用的节点不进任何 thread
        edge_count = sum(len(adjacency.get(v, ())) for v in component) // 2
        has_self_loop = bool(self_loops.get(component[0])) if len(component) == 1 else False
        if edge_count > 0 or has_self_loop:
            if (edge_count >= len(component) and len(component) > 1) or has_self_loop:
                cycle_path = _find_cycle(component, adjacency)
                if not cycle_path and has_self_loop:
                    cycle_path = [component[0]]
                if cycle_path:
                    result.cycles.append(cycle_path)
            root = find(component[0])
            tid = f"thread-{root[:16]}" if root else "thread-anon"
            result.thread_ids[root] = tid
            for v in sorted(component):
                result.members[v] = tid
            result.threads.append(sorted(component))

    # 自引用也登记为环（单节点环）
    for mid in result.self_references:
        result.cycles.append([mid])

    # 去重 cycles
    unique_cycles: list[list[str]] = []
    seen_sig: set[tuple[str, ...]] = set()
    for cyc in result.cycles:
        sig = tuple(sorted(cyc))
        if sig not in seen_sig:
            seen_sig.add(sig)
            unique_cycles.append(cyc)
    result.cycles = unique_cycles
    return result


def _find_cycle(component: list[str], adjacency: dict[str, set[str]]) -> list[str]:
    """在无向分量内用迭代 DFS 找到一条回边并还原环（显式栈，永不递归爆栈）。"""
    color: dict[str, int] = {v: 0 for v in component}  # 0 white 1 gray 2 black
    parent: dict[str, str] = {}
    found: list[str] = []

    for root in component:
        if color[root] != 0 or found:
            continue
        # 栈元素：(节点, 邻接迭代器)
        stack: list[tuple[str, iter]] = [(root, iter(adjacency.get(root, ())))]
        color[root] = 1
        while stack:
            u, it = stack[-1]
            advanced = False
            for v in it:
                cv = color.get(v, 2)
                if cv == 0:
                    parent[v] = u
                    color[v] = 1
                    stack.append((v, iter(adjacency.get(v, ()))))
                    advanced = True
                    break
                if cv == 1 and parent.get(u) != v:
                    # 回边 u-v：还原 v -> ... -> u -> v
                    path = [v]
                    cur = u
                    guard = 0
                    while cur != v and cur in parent and guard <= len(component) + 1:
                        path.append(cur)
                        cur = parent[cur]
                        guard += 1
                    path.append(v)
                    found.extend(reversed(path[:-1]))
                    return found
            if not advanced and not found:
                color[u] = 2
                stack.pop()
    return found
