# -*- coding: utf-8 -*-
"""
ARM64 函数调用图与调用链反查分析器 (Call Graph Analyzer: Callers & Callees)

通过纯 Python 极速扫描 ARM64 指令段中的 BL（Branch with Link）及 Tail-call 分支指令，
构建函数间的完整调用拓扑图，支持：
1. Callers 反查：查找谁调用了目标函数（上游调用链追踪）
2. Callees 正查：查找目标函数内部调用了哪些子函数（下游依赖树分析）
3. 多级调用拓扑树 (Deep Call Tree)：支持递归多层遍历 (--depth N) 与环路检测
4. Mermaid / DOT 可视化拓扑图导出
"""

import bisect
import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CallEdge:
    """单条调用边"""
    caller_va: int            # 所属上层函数入口 VA
    caller_offset: int        # 所属上层函数入口文件偏移
    call_site_va: int         # 实际发出 BL 指令的指令 VA
    call_site_offset: int     # 实际发出 BL 指令的文件偏移
    target_va: int            # 被调用目标函数入口 VA
    target_offset: int        # 被调用目标函数入口文件偏移


@dataclass
class CallTreeNode:
    """多级调用拓扑树节点"""
    va: int                                 # 节点函数入口 VA
    offset: int                             # 节点文件偏移
    label: str                              # 节点显示标签 (如 func@0x1234)
    depth: int                              # 所处层级深度 (0 为根节点)
    call_site_va: Optional[int] = None      # 触发调用的指令 VA
    call_site_offset: Optional[int] = None  # 触发调用的指令文件偏移
    children: List["CallTreeNode"] = field(default_factory=list)
    is_cycle: bool = False                  # 是否为环路递归调用截断点
    demangled_name: Optional[str] = None    # C++ 或 Swift 还原名


@dataclass
class CallGraphReport:
    """调用图分析报告"""
    target_va: int
    target_offset: int
    target_label: str
    callers: List[CallEdge] = field(default_factory=list)
    callees: List[CallEdge] = field(default_factory=list)


class CallGraphAnalyzer:
    """ARM64 函数调用关系分析引擎"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._data: bytes = b""
        self._slice_offset: int = 0
        self._image_base: int = 0
        self._text_va: int = 0
        self._text_file_off: int = 0
        self._text_size: int = 0
        self._sorted_funcs: List[int] = []
        self._initialized: bool = False

        # target_va -> List[CallEdge] (谁调用了 target)
        self._caller_map: Dict[int, List[CallEdge]] = {}
        # caller_func_va -> List[CallEdge] (caller 调用了谁)
        self._callee_map: Dict[int, List[CallEdge]] = {}

    def initialize(self):
        """延迟初始化，构建函数列表与调用图"""
        if self._initialized:
            return
        self._initialized = True

        from .xref_scanner import XrefScanner
        scanner = XrefScanner(self.file_path)
        scanner.scan()

        self._data = scanner._data
        self._slice_offset = scanner._slice_offset
        self._image_base = scanner._image_base or 0x100000000
        self._text_va = scanner._text_va
        self._text_file_off = scanner._text_file_off
        self._text_size = scanner._text_size
        self._sorted_funcs = scanner._sorted_func_starts

        self._build_call_graph()

    def _build_call_graph(self):
        """扫描 __text 段中所有 BL 指令建立调用网格"""
        if not self._text_size or not self._data:
            return

        data = self._data
        ts = self._text_file_off
        te = min(ts + self._text_size, len(data))
        text_va = self._text_va
        sorted_funcs = self._sorted_funcs

        total_instrs = (te - ts) // 4
        for idx in range(total_instrs):
            off = ts + idx * 4
            if off + 4 > len(data):
                break
            instr = struct.unpack_from("<I", data, off)[0]

            # BL 指令: bit[31:26] == 100101 (0x25)
            if (instr >> 26) & 0x3F == 0x25:
                imm26 = instr & 0x03FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= (1 << 26)
                call_site_va = text_va + idx * 4
                target_va = call_site_va + imm26 * 4

                # 仅保留落在 __text 范围内的有效调用
                if text_va <= target_va < text_va + self._text_size:
                    # 确定指令所属的 caller 函数
                    caller_fva = self._nearest_func(call_site_va, sorted_funcs, text_va)
                    caller_foff = ts + (caller_fva - text_va)
                    target_foff = ts + (target_va - text_va)

                    edge = CallEdge(
                        caller_va=caller_fva,
                        caller_offset=caller_foff,
                        call_site_va=call_site_va,
                        call_site_offset=off,
                        target_va=target_va,
                        target_offset=target_foff
                    )

                    self._caller_map.setdefault(target_va, []).append(edge)
                    self._callee_map.setdefault(caller_fva, []).append(edge)

    def get_callers(self, target_va_or_offset: int) -> List[CallEdge]:
        """获取调用了指定目标函数的所有上游调用者 (Callers)"""
        self.initialize()
        va, _ = self._normalize_address(target_va_or_offset)
        edges = self._caller_map.get(va, [])
        if not edges:
            fva = self._nearest_func(va, self._sorted_funcs, self._text_va)
            if fva != va:
                edges = self._caller_map.get(fva, [])
        return edges

    def get_callees(self, target_va_or_offset: int, from_exact_addr: bool = False) -> List[CallEdge]:
        """获取指定函数内部调用的所有下游子函数 (Callees)"""
        self.initialize()
        va, _ = self._normalize_address(target_va_or_offset)
        fva = self._nearest_func(va, self._sorted_funcs, self._text_va)
        edges = self._callee_map.get(fva, [])
        if from_exact_addr and va > fva:
            return [e for e in edges if e.call_site_va >= va]
        return edges

    def build_call_tree(
        self,
        target_va_or_offset: int,
        mode: str = "callees",
        max_depth: int = 2,
        max_children_per_node: int = 15
    ) -> CallTreeNode:
        """构建递归多级调用拓扑树，带环路检测与路径截断"""
        self.initialize()
        target_va, target_foff = self._normalize_address(target_va_or_offset)
        fva = self._nearest_func(target_va, self._sorted_funcs, self._text_va)

        root = CallTreeNode(
            va=fva,
            offset=self._text_file_off + (fva - self._text_va),
            label=f"func@0x{fva:X}" if fva == target_va else f"loc@0x{target_va:X} (in func@0x{fva:X})",
            depth=0
        )

        visited_path = {fva}
        self._expand_tree_node(root, mode, max_depth, max_children_per_node, visited_path)
        return root

    def _expand_tree_node(
        self,
        node: CallTreeNode,
        mode: str,
        max_depth: int,
        max_children: int,
        active_path: Set[int]
    ):
        if node.depth >= max_depth:
            return

        if mode == "callers":
            edges = self.get_callers(node.va)
        else:
            edges = self.get_callees(node.va)

        seen_targets = set()
        count = 0
        for edge in edges:
            child_va = edge.caller_va if mode == "callers" else edge.target_va
            child_foff = edge.caller_offset if mode == "callers" else edge.target_offset
            call_site_va = edge.call_site_va

            if child_va in seen_targets:
                continue
            seen_targets.add(child_va)

            is_cycle = child_va in active_path

            child_node = CallTreeNode(
                va=child_va,
                offset=child_foff,
                label=f"func@0x{child_va:X}",
                depth=node.depth + 1,
                call_site_va=call_site_va,
                call_site_offset=edge.call_site_offset,
                is_cycle=is_cycle
            )
            node.children.append(child_node)
            count += 1
            if count >= max_children:
                break

            if not is_cycle:
                new_path = active_path | {child_va}
                self._expand_tree_node(child_node, mode, max_depth, max_children, new_path)

    def _normalize_address(self, addr: int) -> Tuple[int, int]:
        """地址归一化 (VA, FileOffset)"""
        if addr >= self._image_base:
            va = addr
            file_off = self._text_file_off + (va - self._text_va)
            return (va, file_off)
        if self._text_file_off <= addr < self._text_file_off + self._text_size:
            file_off = addr
            va = self._text_va + (file_off - self._text_file_off)
            return (va, file_off)
        va = self._image_base + addr
        file_off = self._text_file_off + (va - self._text_va)
        return (va, file_off)

    @staticmethod
    def _nearest_func(va: int, sorted_funcs: List[int], text_va: int) -> int:
        if not sorted_funcs:
            return text_va
        idx = bisect.bisect_right(sorted_funcs, va)
        if idx > 0:
            return sorted_funcs[idx - 1]
        return sorted_funcs[0] if sorted_funcs else text_va

    @classmethod
    def format_console_tree(cls, root: CallTreeNode, prefix: str = "", is_last: bool = True) -> List[str]:
        """格式化为控制台树状结构字符串"""
        lines = []
        if root.depth == 0:
            lines.append(f"\033[1;32m[● Root] {root.label}\033[0m")
        else:
            connector = "└── " if is_last else "├── "
            cs_str = f" \033[90m(CallSite: 0x{root.call_site_va:X})\033[0m" if root.call_site_va else ""
            cycle_str = " \033[91m[Cycle/Recursion]\033[0m" if root.is_cycle else ""
            lines.append(f"{prefix}{connector}\033[96m{root.label}\033[0m{cs_str}{cycle_str}")

        child_prefix = prefix + ("    " if is_last else "│   ")
        count = len(root.children)
        for i, child in enumerate(root.children):
            c_last = (i == count - 1)
            lines.extend(cls.format_console_tree(child, child_prefix, c_last))
        return lines

    @classmethod
    def format_mermaid(cls, root: CallTreeNode, mode: str = "callees", title: str = "") -> str:
        """导出为 Markdown Mermaid 流程图"""
        chart_title = title or ("下游子调用树 (Callees Tree)" if mode == "callees" else "上游调用链 (Callers Tree)")
        lines = [
            "```mermaid",
            f"---",
            f"title: {chart_title}",
            f"---",
            "graph TD",
            "    %% Styles",
            "    classDef rootNode fill:#4CAF50,stroke:#2E7D32,stroke-width:2px,color:#fff,font-weight:bold;",
            "    classDef childNode fill:#1E88E5,stroke:#1565C0,stroke-width:1.5px,color:#fff;",
            "    classDef cycleNode fill:#E53935,stroke:#B71C1C,stroke-width:1.5px,color:#fff;",
            ""
        ]

        node_ids: Dict[int, str] = {}
        counter = [0]

        def get_node_id(va: int) -> str:
            if va not in node_ids:
                node_ids[va] = f"N_{counter[0]}"
                counter[0] += 1
            return node_ids[va]

        def traverse(node: CallTreeNode):
            u_id = get_node_id(node.va)
            for child in node.children:
                v_id = get_node_id(child.va)
                edge_label = f"BL @ 0x{child.call_site_va:X}" if child.call_site_va else "Call"
                if mode == "callers":
                    # Caller 指向 Target
                    lines.append(f'    {v_id}["{child.label}"] -->|"{edge_label}"| {u_id}["{node.label}"]')
                else:
                    # Target 指向 Callee
                    lines.append(f'    {u_id}["{node.label}"] -->|"{edge_label}"| {v_id}["{child.label}"]')

                if child.is_cycle:
                    lines.append(f"    class {v_id} cycleNode;")
                else:
                    lines.append(f"    class {v_id} childNode;")

                if not child.is_cycle:
                    traverse(child)

        root_id = get_node_id(root.va)
        lines.append(f'    {root_id}["{root.label}"]:::rootNode')
        traverse(root)
        lines.append("```\n")
        return "\n".join(lines)
