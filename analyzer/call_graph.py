# -*- coding: utf-8 -*-
"""
ARM64 函数调用图与调用链反查分析器 (Call Graph Analyzer: Callers & Callees)

通过纯 Python 极速扫描 ARM64 指令段中的 BL（Branch with Link）及 Tail-call 分支指令，
构建函数间的完整调用拓扑图，支持：
1. Callers 反查：查找谁调用了目标函数（上游调用链追踪）
2. Callees 正查：查找目标函数内部调用了哪些子函数（下游依赖树分析）
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
        # 兼容直接命中函数入口或目标指令
        edges = self._caller_map.get(va, [])
        if not edges:
            # 若 va 稍微偏离，寻找最近的函数入口重试
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
        # 相对基址 RVA
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
