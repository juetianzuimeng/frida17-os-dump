# -*- coding: utf-8 -*-
"""
Headless 反汇编与代码片段提取桥接模块 (Disassembler Bridge)
支持根据十六进制偏移、函数起始 VA、类方法名或符号关键字提取精准的 ARM64 汇编指令片段。
原生支持 Capstone 高性能引擎与 otool 降级兜底，并支持常量字符串与系统调用智能内联注释。
"""

import os
import re
import struct
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


@dataclass
class DisasmInstruction:
    """单条反汇编指令"""
    address: int              # 指令虚拟地址 (VA)
    file_offset: int          # 二进制文件绝对偏移
    bytes_hex: str            # 机器码 Hex (例如: "08 04 00 b0")
    mnemonic: str             # 助记符 (例如: "adrp")
    op_str: str               # 操作数 (例如: "x8, #0x10026a000")
    comment: str = ""         # 智能分析注释 (如字符串常量、系统调用提示等)

    def to_string(self, color: bool = True) -> str:
        if color:
            c_addr = "\033[96m"
            c_bytes = "\033[90m"
            c_mne = "\033[1;33m" if self.mnemonic not in ("b", "bl", "ret", "retab", "svc") else "\033[1;35m"
            c_cmt = "\033[32m"
            c_reset = "\033[0m"
            cmt_str = f"  {c_cmt}; {self.comment}{c_reset}" if self.comment else ""
            return f"  {c_addr}0x{self.address:08X}{c_reset} {c_bytes}[{self.bytes_hex:11s}]{c_reset}  {c_mne}{self.mnemonic:8s}{c_reset} {self.op_str:<26s}{cmt_str}"
        else:
            cmt_str = f"  ; {self.comment}" if self.comment else ""
            return f"  0x{self.address:08X} [{self.bytes_hex:11s}]  {self.mnemonic:8s} {self.op_str:<26s}{cmt_str}"


@dataclass
class DisasmFunction:
    """反汇编函数块"""
    title: str
    start_va: int
    start_offset: int
    end_va: int
    instructions: List[DisasmInstruction] = field(default_factory=list)
    total_bytes: int = 0

    def format_code(self, color: bool = True) -> str:
        lines = []
        c_title = "\033[1;34m" if color else ""
        c_reset = "\033[0m" if color else ""
        lines.append(f"{c_title}=== [Disasm] {self.title} (VA: 0x{self.start_va:X}, Offset: 0x{self.start_offset:X}, Size: {self.total_bytes}B) ==={c_reset}")
        for insn in self.instructions:
            lines.append(insn.to_string(color=color))
        return "\n".join(lines)


class Disassembler:
    """ARM64 反汇编与分析桥接引擎"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._data: bytes = b""
        self._slice_offset: int = 0
        self._slice_size: int = 0
        self._image_base: int = 0
        self._text_va: int = 0
        self._text_file_off: int = 0
        self._text_size: int = 0
        self._func_starts: Set[int] = set()
        self._va_to_string: Dict[int, str] = {}
        self._initialized: bool = False

    def initialize(self):
        """延迟按需解析 Mach-O 基本段与函数起始信息"""
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
        self._func_starts = scanner._func_starts
        self._va_to_string = scanner._va_to_string

    def resolve_target(self, target: str) -> List[Tuple[str, int]]:
        """
        将用户输入的 target 解析为一个或多个函数起始 VA。
        target 可以是：
        1. 十六进制偏移/地址 (如 '0x1E9B34' 或 '1E9B34')
        2. 字符串关键词 (从 xrefs 交叉引用定位调用者函数)
        """
        self.initialize()
        results: List[Tuple[str, int]] = []

        # 尝试作为十六进制地址解析
        clean_target = target.strip()
        is_hex = False
        val = 0
        try:
            if clean_target.lower().startswith("0x"):
                val = int(clean_target, 16)
                is_hex = True
            elif all(c in "0123456789abcdefABCDEF" for c in clean_target) and len(clean_target) >= 3:
                val = int(clean_target, 16)
                is_hex = True
        except ValueError:
            is_hex = False

        if is_hex:
            va, foff = self._normalize_address(val)
            # 若落在 text 段内，寻找最近的函数起始
            fva = self._nearest_func_start(va)
            label = f"func@0x{fva:X}" if fva == va else f"loc@0x{va:X} (in func@0x{fva:X})"
            results.append((label, va))
            return results

        # 文本关键词：通过 xrefs 反查引用它的函数
        from .xref_scanner import XrefScanner
        scanner = XrefScanner(self.file_path)
        hits = scanner.scan_for([clean_target])
        seen_funcs = set()
        for h in hits.query(clean_target):
            fva = h.caller_func_va
            if fva not in seen_funcs:
                seen_funcs.add(fva)
                results.append((f"xref-caller: func@0x{fva:X} -> '{h.target_content[:40]}'", fva))

        return results

    def disasm_at(
        self,
        target_va_or_offset: int,
        max_instructions: int = 50,
        stop_at_ret: bool = True
    ) -> DisasmFunction:
        """从指定 VA 或文件偏移开始反汇编"""
        self.initialize()
        va, file_offset = self._normalize_address(target_va_or_offset)

        func_title = f"func@0x{va:X}"
        if va in self._func_starts:
            func_title = f"func@0x{va:X} [Exported/Function Start]"

        if HAS_CAPSTONE:
            return self._disasm_capstone(va, file_offset, func_title, max_instructions, stop_at_ret)
        else:
            return self._disasm_otool(va, file_offset, func_title, max_instructions)

    def _normalize_address(self, addr: int) -> Tuple[int, int]:
        """将任意格式地址（VA、RVA 或文件偏移）归一化为 (VA, FileOffset)"""
        # 1. 已经是虚拟地址 (VA)
        if addr >= self._image_base:
            va = addr
            file_off = self._text_file_off + (va - self._text_va)
            return (va, file_off)

        # 2. 如果是文件绝对偏移
        if self._text_file_off <= addr < self._text_file_off + self._text_size:
            file_off = addr
            va = self._text_va + (file_off - self._text_file_off)
            return (va, file_off)

        # 3. 相对基址的 RVA (如 0x1E9B34)
        rva = addr
        va = self._image_base + rva
        file_off = self._text_file_off + (va - self._text_va)
        return (va, file_off)

    def _nearest_func_start(self, va: int) -> int:
        best = va
        for fva in self._func_starts:
            if fva <= va and (best == va or fva > best):
                best = fva
        return best

    def _disasm_capstone(
        self,
        va: int,
        file_offset: int,
        title: str,
        max_instructions: int,
        stop_at_ret: bool
    ) -> DisasmFunction:
        func = DisasmFunction(
            title=title,
            start_va=va,
            start_offset=file_offset,
            end_va=va
        )

        read_size = max_instructions * 4
        if file_offset < 0 or file_offset + read_size > len(self._data):
            # 越界保护
            read_size = max(0, len(self._data) - max(0, file_offset))
            if read_size <= 0:
                return func

        code_bytes = self._data[file_offset:file_offset + read_size]
        cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        cs.detail = True

        pending_adrp: Dict[int, int] = {}
        count = 0

        for insn in cs.disasm(code_bytes, va):
            count += 1
            cur_off = file_offset + (insn.address - va)
            bytes_hex = " ".join(f"{b:02x}" for b in insn.bytes)
            comment = ""

            # 智能注释分析
            if insn.mnemonic == "adrp":
                rd = insn.operands[0].reg
                imm = insn.operands[1].imm
                pending_adrp[rd] = imm
            elif insn.mnemonic == "add" and len(insn.operands) >= 3:
                rd = insn.operands[0].reg
                rn = insn.operands[1].reg
                imm = insn.operands[2].imm
                if rn in pending_adrp:
                    target_va = pending_adrp.pop(rn) + imm
                    s = self._va_to_string.get(target_va)
                    if s:
                        disp_str = s.replace("\n", "\\n")
                        comment = f'"{disp_str[:45]}"'
                    else:
                        comment = f"0x{target_va:X}"
            elif insn.mnemonic == "ldr" and len(insn.operands) >= 2:
                rn = insn.operands[1].value.mem.base if insn.operands[1].type == capstone.arm64.ARM64_OP_MEM else None
                disp = insn.operands[1].value.mem.disp if insn.operands[1].type == capstone.arm64.ARM64_OP_MEM else 0
                if rn in pending_adrp:
                    target_va = pending_adrp.pop(rn) + disp
                    s = self._va_to_string.get(target_va)
                    if s:
                        disp_str = s.replace("\n", "\\n")
                        comment = f'"{disp_str[:45]}"'
                    else:
                        comment = f"0x{target_va:X}"
            elif insn.mnemonic == "svc":
                comment = "Supervisor Call (Syscall / Mach Trap)"
            elif insn.mnemonic in ("ret", "retab"):
                comment = "[End of Function / Return]"

            func.instructions.append(DisasmInstruction(
                address=insn.address,
                file_offset=cur_off,
                bytes_hex=bytes_hex,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                comment=comment
            ))

            func.end_va = insn.address + 4
            func.total_bytes += 4

            if stop_at_ret and insn.mnemonic in ("ret", "retab"):
                break
            if count >= max_instructions:
                break

        return func

    def _disasm_otool(
        self,
        va: int,
        file_offset: int,
        title: str,
        max_instructions: int
    ) -> DisasmFunction:
        """使用系统 otool 命令行作为 fallback 反汇编引擎"""
        func = DisasmFunction(
            title=title,
            start_va=va,
            start_offset=file_offset,
            end_va=va
        )
        try:
            p = subprocess.run(
                ["otool", "-tV", self.file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if p.returncode != 0:
                return func

            capturing = False
            count = 0
            hex_va_prefix = f"{va:x}"

            for line in p.stdout.splitlines():
                if hex_va_prefix in line.lower():
                    capturing = True

                if capturing:
                    parts = line.strip().split(maxsplit=2)
                    if len(parts) >= 2:
                        insn_addr_str = parts[0]
                        mne = parts[1]
                        op = parts[2] if len(parts) > 2 else ""
                        try:
                            curr_va = int(insn_addr_str, 16)
                        except ValueError:
                            continue
                        func.instructions.append(DisasmInstruction(
                            address=curr_va,
                            file_offset=file_offset + (curr_va - va),
                            bytes_hex="",
                            mnemonic=mne,
                            op_str=op,
                            comment=""
                        ))
                        count += 1
                        if mne in ("ret", "retab") or count >= max_instructions:
                            break
        except Exception:
            pass

        return func
