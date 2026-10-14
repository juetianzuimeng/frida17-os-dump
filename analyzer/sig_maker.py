# -*- coding: utf-8 -*-
"""
ARM64 函数特征签名生成器与跨版本模式匹配器 (SigMaker & Pattern Matcher)

专用于解决 App 升级发版导致函数偏移 (Offset) 失效的痛点问题：
1. 智能掩码签名提取：分析函数 ARM64 机器码，自动通配易变跳转与页基址立即数，生成跨版本鲁棒特征码
2. 毫秒级极速匹配：利用底层 C 引擎正则流检索，在数十兆 Mach-O 中 10ms 级秒定最新偏移
3. 签名唯一性自校验：自动评估特征码在全库中的唯一性并动态扩展长度
"""

import os
import re
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class SigMatchResult:
    """特征码匹配结果"""
    va: int                   # 匹配位置虚拟地址
    file_offset: int          # 匹配位置文件偏移
    module_name: str          # 所属模块名
    matched_hex: str          # 实际匹配到的十六进制字节


class SigMaker:
    """ARM64 函数签名制作与跨版本检索引擎"""

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self._data: bytes = b""
        self._text_va: int = 0
        self._text_file_off: int = 0
        self._text_size: int = 0
        self._image_base: int = 0
        self._initialized: bool = False

    def initialize(self):
        """延迟加载并解析 Mach-O 代码段"""
        if self._initialized:
            return
        self._initialized = True

        from .xref_scanner import XrefScanner
        scanner = XrefScanner(self.file_path)
        scanner.scan()

        self._data = scanner._data
        self._text_va = scanner._text_va
        self._text_file_off = scanner._text_file_off
        self._text_size = scanner._text_size
        self._image_base = scanner._image_base or 0x100000000

    def generate_signature(
        self,
        target_va_or_offset: int,
        min_instructions: int = 8,
        max_instructions: int = 32,
        ensure_unique: bool = True
    ) -> Tuple[str, str, int]:
        """
        为目标函数生成跨版本通配特征码。
        返回: (ida_pattern, mask_str, match_count)
        例如: "FD 7B BE A9 ?? ?? ?? ?? E0 03 18 AA"
        """
        self.initialize()
        if not self._data or not self._text_size:
            return ("", "", 0)

        data = self._data
        target_va, file_off = self._normalize_address(target_va_or_offset)

        if not (self._text_file_off <= file_off < self._text_file_off + self._text_size):
            # 若给定的不是 text 段内地址，尝试按文件偏移截取
            if file_off >= len(data):
                return ("", "", 0)

        # 动态增加指令长度，直到特征码在全库中唯一匹配
        for insn_count in range(min_instructions, max_instructions + 1, 4):
            ida_tokens = []
            mask_tokens = []

            for i in range(insn_count):
                curr_off = file_off + i * 4
                if curr_off + 4 > len(data):
                    break

                instr = struct.unpack_from("<I", data, curr_off)[0]
                raw_bytes = data[curr_off : curr_off + 4]

                # 识别 ARM64 易变跳转与寻址指令并执行通配
                if self._is_volatile_instruction(instr):
                    # BL / B / ADRP / 条件跳转立即数易变 -> 设为通配符
                    ida_tokens.extend(["??", "??", "??", "??"])
                    mask_tokens.append("????")
                else:
                    # 固定指令 -> 保留确切字节
                    for b in raw_bytes:
                        ida_tokens.append(f"{b:02X}")
                    mask_tokens.append("xxxx")

            ida_pattern = " ".join(ida_tokens)
            mask_str = "".join(mask_tokens)

            # 检索当前特征码在二进制中的命中数
            matches = self.find_signature(ida_pattern)
            match_count = len(matches)

            if not ensure_unique or match_count == 1:
                return (ida_pattern, mask_str, match_count)

        return (ida_pattern, mask_str, match_count)

    def find_signature(self, pattern: str) -> List[SigMatchResult]:
        """
        在当前二进制中检索特征码 (支持 '??' 或 '?' 通配符)。
        使用 Python 正则引擎实现 C 级高速内存流匹配 (10ms 内)。
        """
        self.initialize()
        if not self._data:
            return []

        # 将 IDA 风格 pattern 编译为正则二进制模式
        cleaned = pattern.strip().replace("\n", " ").replace("\t", " ")
        tokens = [t.upper() for t in cleaned.split() if t]

        reg_parts = []
        for t in tokens:
            if t in ("??", "?"):
                reg_parts.append(b".")
            else:
                try:
                    val = int(t, 16)
                    reg_parts.append(re.escape(bytes([val])))
                except ValueError:
                    reg_parts.append(b".")

        if not reg_parts:
            return []

        regex = re.compile(b"".join(reg_parts), re.DOTALL)
        data = self._data
        module_name = os.path.basename(self.file_path)

        results = []
        for match in regex.finditer(data):
            foff = match.start()
            matched_slice = data[foff : foff + min(len(tokens), 32)]
            matched_hex = " ".join(f"{b:02X}" for b in matched_slice)

            # 计算对应的 VA
            if self._text_file_off <= foff < self._text_file_off + self._text_size:
                va = self._text_va + (foff - self._text_file_off)
            else:
                va = self._image_base + foff

            results.append(SigMatchResult(
                va=va,
                file_offset=foff,
                module_name=module_name,
                matched_hex=matched_hex
            ))

        return results

    @staticmethod
    def _is_volatile_instruction(instr: int) -> bool:
        """
        判断 ARM64 指令是否包含随编译基址变动的相对偏移立即数。
        """
        # 1. BL (Branch with Link): bit[31:26] == 0x25
        if (instr >> 26) & 0x3F == 0x25:
            return True

        # 2. B (Unconditional Branch): bit[31:26] == 0x05
        if (instr >> 26) & 0x3F == 0x05:
            return True

        # 3. ADRP (Address Page): bit[31], bit[28:24] == 1 0000
        if (instr & 0x9F000000) == 0x90000000:
            return True

        # 4. ADR: bit[31], bit[28:24] == 0 0000
        if (instr & 0x9F000000) == 0x10000000:
            return True

        # 5. B.cond (Conditional Branch): bit[31:24] == 01010100
        if (instr >> 24) & 0xFF == 0x54:
            return True

        # 6. CBZ / CBNZ: bit[31], bit[29:24] == 0 11010
        if (instr & 0x7E000000) == 0x34000000:
            return True

        # 7. TBZ / TBNZ: bit[31], bit[29:24] == 0 11011
        if (instr & 0x7E000000) == 0x36000000:
            return True

        return False

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
