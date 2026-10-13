# -*- coding: utf-8 -*-
"""
ARM64 交叉引用扫描器 (Cross-Reference Scanner)

基于纯 Python 解析 ARM64 指令流，定位哪些函数体引用了特定的
字符串地址（__cstring / __objc_methname / __objc_classname）、
导入 stub 桩（如 ptrace、sysctl、fork、system）或 ObjC 选择子地址。

核心原理：
    ARM64 的 PC 相对寻址由两条指令完成：
      ADRP  Xn, #page_imm      ; 计算 4K 页地址
      ADD   Xn, Xn, #page_off  ; 加上页内偏移（访问全局/只读数据）
      或
      LDR   Xn, [Xn, #page_off]; 加载指针（访问 got stub）

    两条指令连续出现（允许中间插入若干无关指令）时，可以还原出
    它们共同寻址的目标 VA（Virtual Address），进而映射到
    __cstring / __objc_* 中的某个字符串或符号。

输出：
    XrefResult  - 单条命中结果，含源函数 VA/offset、目标 VA、目标内容
    XrefReport  - 以目标字符串/符号为键的完整交叉引用报表
"""

import os
import struct
import bisect
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set


# Mach-O 魔数
FAT_MAGIC    = 0xCAFEBABE
FAT_CIGAM    = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
MH_MAGIC_64  = 0xFEEDFACF
MH_CIGAM_64  = 0xCFFAEDFE
MH_MAGIC     = 0xFEEDFACE
MH_CIGAM     = 0xCEFAEDFE
CPU_TYPE_ARM64  = 0x01000000 | 12
CPU_TYPE_ARM    = 12
CPU_TYPE_X86_64 = 0x01000000 | 7


@dataclass
class XrefResult:
    """单条交叉引用命中记录"""
    caller_va: int          # 引用指令所在的虚拟地址
    caller_offset: int      # 引用指令在文件中的字节偏移
    caller_func_va: int     # 包含该引用的函数起始 VA
    caller_func_offset: int # 函数起始在文件中的字节偏移
    target_va: int          # 被引用目标的虚拟地址
    target_content: str     # 被引用目标的可读内容（字符串或符号名）
    instr_type: str = "ADRP+ADD"

    @property
    def caller_func_hex(self) -> str:
        return f"0x{self.caller_func_offset:X}"

    @property
    def caller_hex(self) -> str:
        return f"0x{self.caller_offset:X}"

    @property
    def target_hex(self) -> str:
        return f"0x{self.target_va:X}"


@dataclass
class XrefReport:
    """完整的交叉引用报表"""
    by_target: Dict[str, List[XrefResult]] = field(default_factory=dict)
    by_caller_offset: Dict[str, XrefResult] = field(default_factory=dict)

    def add(self, result: XrefResult):
        self.by_target.setdefault(result.target_content, []).append(result)
        self.by_caller_offset[result.caller_hex] = result

    def query(self, keyword: str) -> List[XrefResult]:
        """按关键词模糊搜索目标内容，返回命中结果列表"""
        kw = keyword.lower()
        results = []
        for k, v in self.by_target.items():
            if kw in k.lower():
                results.extend(v)
        return results

    @property
    def total(self) -> int:
        return len(self.by_caller_offset)


class XrefScanner:
    """
    ARM64 Mach-O 交叉引用扫描器

    用法:
        scanner = XrefScanner("/path/to/binary")
        report  = scanner.scan()
        hits    = report.query("ptrace")
        for r in hits:
            print(f"  函数偏移: {r.caller_func_hex}  -> '{r.target_content}'")
    """

    MAX_WINDOW = 6  # ADRP 后等待配对的最大指令数

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._data: bytes = b""
        self._slice_offset: int = 0
        self._image_base: int = 0
        self._text_va: int = 0
        self._text_file_off: int = 0
        self._text_size: int = 0
        self._va_to_string: Dict[int, str] = {}
        self._func_starts: Set[int] = set()
        self._sorted_func_starts: List[int] = []

    def scan(self) -> XrefReport:
        """完整扫描，返回交叉引用报表"""
        report = XrefReport()
        try:
            with open(self.file_path, "rb") as f:
                self._data = f.read()
            slice_offset, slice_size, _ = self._select_arm64_slice()
            if slice_offset < 0:
                return report
            self._slice_offset = slice_offset
            self._parse_segments_and_strings()
            self._parse_function_starts()
            if not self._func_starts:
                self._heuristic_scan_prologues()
            self._sorted_func_starts = sorted(self._func_starts)
            self._scan_text_section(report)
        except Exception:
            pass
        return report

    def scan_for(self, keywords: List[str]) -> XrefReport:
        """只对特定关键词命中的字符串进行检索（性能优化版）"""
        full = self.scan()
        filtered = XrefReport()
        for kw in keywords:
            for r in full.query(kw):
                filtered.add(r)
        return filtered

    # ── 切片选择 ──────────────────────────────────────────────────────────────
    def _select_arm64_slice(self) -> Tuple[int, int, str]:
        data = self._data
        if len(data) < 8:
            return (-1, 0, "")
        magic = struct.unpack_from(">I", data, 0)[0]

        if magic in (FAT_MAGIC, FAT_CIGAM):
            endian = ">" if magic == FAT_MAGIC else "<"
            nfat = struct.unpack_from(f"{endian}I", data, 4)[0]
            pos, best = 8, None
            for _ in range(nfat):
                if pos + 20 > len(data): break
                ct, cs, off, sz, _ = struct.unpack_from(f"{endian}5I", data, pos)
                arch = self._cpu_arch(ct, cs); pos += 20
                if "arm64" in arch: return (off, sz, arch)
                if best is None: best = (off, sz, arch)
            return best if best else (-1, 0, "")

        elif magic in (FAT_MAGIC_64, FAT_CIGAM_64):
            endian = ">" if magic == FAT_MAGIC_64 else "<"
            nfat = struct.unpack_from(f"{endian}I", data, 4)[0]
            pos, best = 8, None
            for _ in range(nfat):
                if pos + 32 > len(data): break
                ct, cs, off, sz, _ = struct.unpack_from(f"{endian}2I2QI", data, pos)
                arch = self._cpu_arch(ct, cs); pos += 32
                if "arm64" in arch: return (off, sz, arch)
                if best is None: best = (off, sz, arch)
            return best if best else (-1, 0, "")

        else:
            le = struct.unpack_from("<I", data, 0)[0]
            if le in (MH_MAGIC_64, MH_CIGAM_64):
                ct, cs = struct.unpack_from("<2I", data, 4)
                return (0, len(data), self._cpu_arch(ct, cs))
            return (-1, 0, "")

    @staticmethod
    def _cpu_arch(cputype: int, cpusubtype: int) -> str:
        if cputype == CPU_TYPE_ARM64:
            return "arm64e" if (cpusubtype & 0xFF) == 2 else "arm64"
        if cputype == CPU_TYPE_ARM:  return "armv7"
        if cputype == CPU_TYPE_X86_64: return "x86_64"
        return f"cpu_{cputype}"

    # ── 段/节解析 ─────────────────────────────────────────────────────────────
    def _parse_segments_and_strings(self):
        data = self._data
        so = self._slice_offset
        if so + 8 > len(data): return

        le_magic = struct.unpack_from("<I", data, so)[0]
        is_64 = le_magic in (MH_MAGIC_64, MH_CIGAM_64)
        endian = "<" if le_magic in (MH_MAGIC, MH_MAGIC_64) else ">"
        hdr_size = 32 if is_64 else 28
        if so + hdr_size > len(data): return

        if is_64:
            _, _, _, ncmds, _, _, _ = struct.unpack_from(f"{endian}7I", data, so + 4)
        else:
            _, _, _, ncmds, _, _ = struct.unpack_from(f"{endian}6I", data, so + 4)

        cmd_pos = so + hdr_size
        LC_SEGMENT_64 = 0x19
        LC_SEGMENT    = 0x01

        for _ in range(ncmds):
            if cmd_pos + 8 > len(data): break
            cmd, cmdsize = struct.unpack_from(f"{endian}2I", data, cmd_pos)
            if cmdsize == 0: break
            if cmd in (LC_SEGMENT_64, LC_SEGMENT):
                self._parse_segment_cmd(data, cmd_pos, endian, cmd == LC_SEGMENT_64)
            cmd_pos += cmdsize

    def _parse_segment_cmd(self, data: bytes, pos: int, endian: str, is_64: bool):
        so = self._slice_offset
        if is_64:
            seg_fmt = f"{endian}16sQQQQIIII"
        else:
            seg_fmt = f"{endian}16sIIIIIIII"
        seg_size = struct.calcsize(seg_fmt)
        if pos + 8 + seg_size > len(data): return

        fields = struct.unpack_from(seg_fmt, data, pos + 8)
        seg_name    = fields[0].rstrip(b"\x00").decode("ascii", errors="ignore")
        seg_vmaddr  = fields[1]
        nsects      = fields[7] if is_64 else fields[6]

        if seg_name == "__TEXT":
            self._image_base = seg_vmaddr

        # Section 结构体大小：64位=80字节 (16+16+8+8+4×8=80)，32位=68字节 (16+16+4+4+4×7=68)
        if is_64:
            sect_fmt = f"{endian}16s16sQQ8I"   # 80 bytes
        else:
            sect_fmt = f"{endian}16s16sI7I"    # 68 bytes
        sect_size = struct.calcsize(sect_fmt)
        sect_pos = pos + 8 + seg_size

        for _ in range(nsects):
            if sect_pos + sect_size > len(data): break
            sf = struct.unpack_from(sect_fmt, data, sect_pos)
            sect_name    = sf[0].rstrip(b"\x00").decode("ascii", errors="ignore")
            sect_seg_n   = sf[1].rstrip(b"\x00").decode("ascii", errors="ignore")
            sect_vmaddr  = sf[2]
            sect_vmsize  = sf[3]
            sect_fileoff = sf[4]
            name_key = f"{sect_seg_n},{sect_name}"

            if name_key == "__TEXT,__text":
                self._text_va       = sect_vmaddr
                self._text_file_off = so + sect_fileoff  # FAT切片内偏移，需加 slice_offset
                self._text_size     = sect_vmsize

            if sect_name in ("__cstring", "__objc_methname", "__objc_classname",
                             "__const", "__cfstring"):
                self._index_cstring_section(data, so + sect_fileoff, sect_vmsize, sect_vmaddr)

            sect_pos += sect_size

    def _index_cstring_section(self, data: bytes, file_off: int, size: int, vmaddr: int):
        end = min(file_off + size, len(data))
        blob = data[file_off:end]
        p = 0
        while p < len(blob):
            nul = blob.find(b"\x00", p)
            if nul == -1: break
            s = blob[p:nul]
            if len(s) >= 3:
                try:
                    text = s.decode("utf-8", errors="replace").strip()
                    if text and len(text) <= 512:
                        self._va_to_string[vmaddr + p] = text
                except Exception:
                    pass
            p = nul + 1

    # ── LC_FUNCTION_STARTS ────────────────────────────────────────────────────
    def _parse_function_starts(self):
        data = self._data
        so = self._slice_offset
        if so + 8 > len(data): return

        le_magic = struct.unpack_from("<I", data, so)[0]
        is_64 = le_magic in (MH_MAGIC_64, MH_CIGAM_64)
        endian = "<" if le_magic in (MH_MAGIC, MH_MAGIC_64) else ">"
        hdr_size = 32 if is_64 else 28
        if so + hdr_size > len(data): return

        if is_64:
            _, _, _, ncmds, _, _, _ = struct.unpack_from(f"{endian}7I", data, so + 4)
        else:
            _, _, _, ncmds, _, _ = struct.unpack_from(f"{endian}6I", data, so + 4)

        cmd_pos = so + hdr_size
        LC_FUNCTION_STARTS = 0x26

        for _ in range(ncmds):
            if cmd_pos + 8 > len(data): break
            cmd, cmdsize = struct.unpack_from(f"{endian}2I", data, cmd_pos)
            if cmdsize == 0: break
            if cmd == LC_FUNCTION_STARTS and cmd_pos + 16 <= len(data):
                dataoff, datasize = struct.unpack_from(f"{endian}2I", data, cmd_pos + 8)
                self._decode_function_starts(data, so + dataoff, datasize)
            cmd_pos += cmdsize

    def _decode_function_starts(self, data: bytes, file_off: int, size: int):
        end = min(file_off + size, len(data))
        pos = file_off
        current_va = self._image_base
        while pos < end:
            val, n = self._read_uleb128(data, pos)
            if n == 0: break
            pos += n
            if val == 0: break
            current_va += val
            self._func_starts.add(current_va)

    @staticmethod
    def _read_uleb128(data: bytes, pos: int) -> Tuple[int, int]:
        result = shift = n = 0
        while pos + n < len(data):
            byte = data[pos + n]; n += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80): break
            if shift > 63: break
        return result, n

    def _heuristic_scan_prologues(self):
        """当 Mach-O 剥离了 LC_FUNCTION_STARTS 时，启发式扫描 ARM64 标准函数序言"""
        data = self._data
        ts = self._text_file_off
        te = min(ts + self._text_size, len(data))
        text_va = self._text_va
        for off in range(ts, te - 4, 4):
            w = struct.unpack_from("<I", data, off)[0]
            # 匹配 pacibsp (0xD503237F) 或 paciasp (0xD503233F)
            if w in (0xD503237F, 0xD503233F):
                self._func_starts.add(text_va + (off - ts))
            # 匹配 stp x29, x30, [sp, ...] (0xA9...FD7B)
            elif (w & 0xFFC07FFF) == 0xA9007BFD:
                self._func_starts.add(text_va + (off - ts))
            # 匹配 stp x20, x19, [sp, #-...]! 等栈帧分配
            elif (w & 0xFFC003FF) == 0xA9800000:
                self._func_starts.add(text_va + (off - ts))

    # ── ARM64 指令扫描 ────────────────────────────────────────────────────────
    def _scan_text_section(self, report: XrefReport):
        if not self._text_size or not self._va_to_string:
            return
        data = self._data
        ts = self._text_file_off
        te = min(ts + self._text_size, len(data))
        text_va = self._text_va
        func_starts = self._sorted_func_starts

        total_instrs = (te - ts) // 4
        # 寄存器 -> (page_va, file_off, instr_va)
        adrp_pending: Dict[int, Tuple[int, int, int]] = {}

        for idx in range(total_instrs):
            off = ts + idx * 4
            if off + 4 > len(data): break
            instr = struct.unpack_from("<I", data, off)[0]
            instr_va = text_va + idx * 4

            # ── ADRP ──────────────────────────────────────────────────────
            # bit[31]=1, bit[29]=1, bit[28:24]=10000 => (instr>>24)&0x9F == 0x90
            if (instr >> 24) & 0x9F == 0x90:
                rd = instr & 0x1F
                immlo = (instr >> 29) & 0x3
                immhi = (instr >> 5) & 0x7FFFF
                imm   = ((immhi << 2) | immlo) << 12
                # 符号扩展 33 位 (21 位 × 4096)
                if imm & (1 << 32):
                    imm -= (1 << 33)
                page_va = (instr_va & ~0xFFF) + imm
                adrp_pending[rd] = (page_va, off, instr_va)
                continue

            # ── ADD Xd, Xn, #imm12 (64-bit immediate) ─────────────────────
            # sf=1, op=0, S=0, 100010 => (instr>>23)&0x1FF == 0x122
            if (instr >> 23) & 0x1FF == 0x122:
                rd    = instr & 0x1F
                rn    = (instr >> 5) & 0x1F
                shift = (instr >> 22) & 0x1
                imm12 = (instr >> 10) & 0xFFF
                if shift == 1: imm12 <<= 12
                if rn in adrp_pending:
                    page_va, adrp_off, adrp_instr_va = adrp_pending.pop(rn)
                    target_va = page_va + imm12
                    if target_va in self._va_to_string:
                        fva  = self._nearest_func(instr_va, func_starts, text_va)
                        foff = self._va_to_foff(fva, text_va, ts)
                        report.add(XrefResult(
                            caller_va=instr_va, caller_offset=off,
                            caller_func_va=fva, caller_func_offset=foff,
                            target_va=target_va,
                            target_content=self._va_to_string[target_va],
                            instr_type="ADRP+ADD"
                        ))
                continue

            # ── LDR Xt, [Xn, #imm12*8] (64-bit unsigned offset) ───────────
            # (instr>>22)&0x3FF == 0x3E5
            if (instr >> 22) & 0x3FF == 0x3E5:
                rd    = instr & 0x1F
                rn    = (instr >> 5) & 0x1F
                imm12 = ((instr >> 10) & 0xFFF) * 8
                if rn in adrp_pending:
                    page_va, adrp_off, adrp_instr_va = adrp_pending.pop(rn)
                    target_va = page_va + imm12
                    if target_va in self._va_to_string:
                        fva  = self._nearest_func(instr_va, func_starts, text_va)
                        foff = self._va_to_foff(fva, text_va, ts)
                        report.add(XrefResult(
                            caller_va=instr_va, caller_offset=off,
                            caller_func_va=fva, caller_func_offset=foff,
                            target_va=target_va,
                            target_content=self._va_to_string[target_va],
                            instr_type="ADRP+LDR"
                        ))
                continue

            # ── BL / B 分支：刷新 ADRP 窗口 ─────────────────────────────────
            if (instr >> 26) & 0x3F in (0x25, 0x05):
                adrp_pending.clear()
                continue

            # 避免过旧的 ADRP 悬空
            if len(adrp_pending) > 32:
                keys = list(adrp_pending.keys())
                for k in keys[:-self.MAX_WINDOW]:
                    del adrp_pending[k]

    @staticmethod
    def _nearest_func(va: int, sorted_funcs: List[int], text_va: int) -> int:
        if not sorted_funcs:
            return text_va
        idx = bisect.bisect_right(sorted_funcs, va)
        if idx > 0:
            return sorted_funcs[idx - 1]
        return sorted_funcs[0] if sorted_funcs else text_va

    @staticmethod
    def _va_to_foff(va: int, text_va: int, text_file_off: int) -> int:
        if va < text_va: return va
        return text_file_off + (va - text_va)
