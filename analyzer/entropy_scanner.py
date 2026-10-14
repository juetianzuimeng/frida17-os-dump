# -*- coding: utf-8 -*-
"""
滑动窗口香农熵 (Shannon Entropy) 扫描器 (Binary Entropy Profiler)

借鉴 REA (Reverse Engineer Anything) 的 BinaryEntropyProfiler 机制：
1. 计算二进制各段 (Sections) 与全局的香农信息熵：H = -∑ p_i * log2(p_i)；
2. 识别数据特征：
   - 低熵 (0.0 ~ 3.5): 零填充区、格式化结构体对齐
   - 中熵 (3.5 ~ 5.5): 文本字符串、ASCII/UTF-8 字面量
   - 代码熵 (5.5 ~ 6.5): 正常 ARM64 汇编指令流
   - 异常高熵 (7.2 ~ 8.0): 强混淆代码块、白盒密钥表 (S-Box)、内嵌压缩 Payload / 密文；
3. 滑动窗口自动合并连续高熵区间，精准输出物理偏移、VA 与可疑类型研判。
"""

import math
import os
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


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


def calculate_entropy(data_chunk: bytes) -> float:
    """计算字节流的香农信息熵 (0.0 ~ 8.0)"""
    if not data_chunk:
        return 0.0
    length = len(data_chunk)
    counts = Counter(data_chunk)
    ent = 0.0
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 3)


@dataclass
class SectionEntropy:
    """Section 级熵值画像"""
    name: str
    va: int
    file_offset: int
    size: int
    entropy: float
    data_type_hint: str


@dataclass
class EntropySpike:
    """异常高熵区间 (连续合并块)"""
    file_offset: int
    va: int
    size: int
    max_entropy: float
    mean_entropy: float
    section_name: str
    assessment: str

    @property
    def offset_hex(self) -> str:
        return f"0x{self.file_offset:X}"

    @property
    def va_hex(self) -> str:
        return f"0x{self.va:X}"


@dataclass
class EntropyReport:
    """熵值扫描全景报表"""
    binary_name: str
    overall_entropy: float
    sections: List[SectionEntropy] = field(default_factory=list)
    spikes: List[EntropySpike] = field(default_factory=list)


class EntropyScanner:
    """Mach-O 二进制香农熵分析引擎"""

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self._data: bytes = b""
        self._slice_offset: int = 0
        self._slice_size: int = 0
        self._sections: List[Dict] = []

    def scan(self, threshold: float = 7.2, chunk_size: int = 2048) -> Optional[EntropyReport]:
        """执行滑动窗口熵值扫描并归纳高熵块"""
        if not os.path.isfile(self.file_path):
            return None

        with open(self.file_path, "rb") as f:
            self._data = f.read()

        slice_off, slice_sz = self._select_arm64_slice()
        if slice_off < 0:
            return None
        self._slice_offset = slice_off
        self._slice_size = slice_sz

        self._parse_sections()
        return self._evaluate_entropy(threshold=threshold, chunk_size=chunk_size)

    def _select_arm64_slice(self) -> Tuple[int, int]:
        data = self._data
        if len(data) < 8:
            return (-1, 0)
        magic = struct.unpack_from(">I", data, 0)[0]

        if magic in (FAT_MAGIC, FAT_CIGAM):
            endian = ">" if magic == FAT_MAGIC else "<"
            nfat = struct.unpack_from(f"{endian}I", data, 4)[0]
            pos, best = 8, None
            for _ in range(nfat):
                if pos + 20 > len(data): break
                ct, cs, off, sz, _ = struct.unpack_from(f"{endian}5I", data, pos)
                if ct == CPU_TYPE_ARM64: return (off, sz)
                if best is None: best = (off, sz)
                pos += 20
            return best if best else (-1, 0)

        elif magic in (FAT_MAGIC_64, FAT_CIGAM_64):
            endian = ">" if magic == FAT_MAGIC_64 else "<"
            nfat = struct.unpack_from(f"{endian}I", data, 4)[0]
            pos, best = 8, None
            for _ in range(nfat):
                if pos + 32 > len(data): break
                ct, cs, off, sz, _ = struct.unpack_from(f"{endian}2I2QI", data, pos)
                if ct == CPU_TYPE_ARM64: return (off, sz)
                if best is None: best = (off, sz)
                pos += 32
            return best if best else (-1, 0)

        else:
            le = struct.unpack_from("<I", data, 0)[0]
            if le in (MH_MAGIC_64, MH_CIGAM_64, MH_MAGIC, MH_CIGAM):
                return (0, len(data))
            return (-1, 0)

    def _parse_sections(self):
        data = self._data
        so = self._slice_offset
        if so + 32 > len(data): return

        le_magic = struct.unpack_from("<I", data, so)[0]
        is_64 = le_magic in (MH_MAGIC_64, MH_CIGAM_64)
        endian = "<" if le_magic in (MH_MAGIC, MH_MAGIC_64) else ">"
        hdr_size = 32 if is_64 else 28
        if so + hdr_size > len(data): return

        if is_64:
            _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from(f"{endian}7I", data, so + 4)
        else:
            _, _, _, ncmds, sizeofcmds, _ = struct.unpack_from(f"{endian}6I", data, so + 4)

        cmd_pos = so + hdr_size
        LC_SEGMENT_64 = 0x19
        LC_SEGMENT    = 0x01

        for _ in range(ncmds):
            if cmd_pos + 8 > len(data): break
            cmd, cmdsize = struct.unpack_from(f"{endian}2I", data, cmd_pos)
            if cmdsize == 0: break

            if cmd in (LC_SEGMENT_64, LC_SEGMENT):
                is_seg64 = (cmd == LC_SEGMENT_64)
                seg_fmt = f"{endian}16sQQQQIIII" if is_seg64 else f"{endian}16sIIIIIIII"
                seg_size = struct.calcsize(seg_fmt)
                if cmd_pos + 8 + seg_size <= len(data):
                    fields = struct.unpack_from(seg_fmt, data, cmd_pos + 8)
                    seg_name = fields[0].rstrip(b"\x00").decode("ascii", errors="ignore")
                    nsects = fields[7] if is_seg64 else fields[6]

                    sect_fmt = f"{endian}16s16sQQ8I" if is_seg64 else f"{endian}16s16sI7I"
                    sect_size = struct.calcsize(sect_fmt)
                    sect_pos = cmd_pos + 8 + seg_size

                    for _ in range(nsects):
                        if sect_pos + sect_size > len(data): break
                        sf = struct.unpack_from(sect_fmt, data, sect_pos)
                        s_name = sf[0].rstrip(b"\x00").decode("ascii", errors="ignore")
                        s_seg  = sf[1].rstrip(b"\x00").decode("ascii", errors="ignore")
                        s_va   = sf[2]
                        s_vmsz = sf[3]
                        s_off  = sf[4]
                        self._sections.append({
                            "name": f"{s_seg}.{s_name}",
                            "seg": s_seg,
                            "sect": s_name,
                            "va": s_va,
                            "size": s_vmsz,
                            "file_off": so + s_off
                        })
                        sect_pos += sect_size

            cmd_pos += cmdsize

    def _evaluate_entropy(self, threshold: float, chunk_size: int) -> EntropyReport:
        data = self._data
        so = self._slice_offset
        sz = self._slice_size
        slice_data = data[so : so + sz]

        overall = calculate_entropy(slice_data)
        report = EntropyReport(
            binary_name=os.path.basename(self.file_path),
            overall_entropy=overall
        )

        # 1. 计算各 Section 平均熵
        for s in self._sections:
            foff = s["file_off"]
            fsz = s["size"]
            if foff + fsz <= len(data) and fsz > 0:
                s_bytes = data[foff : foff + fsz]
                s_ent = calculate_entropy(s_bytes)
                hint = "代码指令" if "text" in s["name"] else ("文本字符串" if "string" in s["name"] else "数据结构/常量")
                if s_ent >= 7.2:
                    hint += " (异常高熵: 疑似加密/混淆)"
                report.sections.append(SectionEntropy(
                    name=s["name"],
                    va=s["va"],
                    file_offset=foff,
                    size=fsz,
                    entropy=s_ent,
                    data_type_hint=hint
                ))

        # 2. 滑动窗口扫描异常高熵块
        raw_spikes = []
        step = chunk_size // 2  # 50% 重叠采样保证连续性
        scan_end = so + sz

        for cur_off in range(so, scan_end, step):
            block = data[cur_off : min(cur_off + chunk_size, scan_end)]
            if len(block) < 256:
                break
            ent = calculate_entropy(block)
            if ent >= threshold:
                sec_name = self._find_section_for_offset(cur_off)
                raw_spikes.append((cur_off, len(block), ent, sec_name))

        # 3. 合并相邻连续高熵区间
        merged = self._merge_spikes(raw_spikes)
        report.spikes = merged

        return report

    def _find_section_for_offset(self, off: int) -> str:
        for s in self._sections:
            if s["file_off"] <= off < s["file_off"] + s["size"]:
                return s["name"]
        return "__UNKNOWN"

    def _offset_to_va(self, off: int) -> int:
        for s in self._sections:
            if s["file_off"] <= off < s["file_off"] + s["size"]:
                return s["va"] + (off - s["file_off"])
        return off

    def _merge_spikes(self, raw_spikes: List[Tuple[int, int, float, str]]) -> List[EntropySpike]:
        """合并重叠或相邻的连续高熵区间"""
        if not raw_spikes:
            return []

        merged: List[EntropySpike] = []
        cur_start, cur_end, cur_max_ent, cur_sum_ent, cur_count, cur_sec = (
            raw_spikes[0][0],
            raw_spikes[0][0] + raw_spikes[0][1],
            raw_spikes[0][2],
            raw_spikes[0][2],
            1,
            raw_spikes[0][3]
        )

        for off, sz, ent, sec in raw_spikes[1:]:
            end_off = off + sz
            # 如果重叠或相邻 (允许微小间隙) 且属于同一个 section
            if off <= cur_end and sec == cur_sec:
                cur_end = max(cur_end, end_off)
                cur_max_ent = max(cur_max_ent, ent)
                cur_sum_ent += ent
                cur_count += 1
            else:
                # 结算当前区间
                total_sz = cur_end - cur_start
                mean_ent = round(cur_sum_ent / cur_count, 3)
                assess = self._assess_spike(cur_sec, cur_max_ent, total_sz)
                merged.append(EntropySpike(
                    file_offset=cur_start,
                    va=self._offset_to_va(cur_start),
                    size=total_sz,
                    max_entropy=cur_max_ent,
                    mean_entropy=mean_ent,
                    section_name=cur_sec,
                    assessment=assess
                ))
                cur_start, cur_end, cur_max_ent, cur_sum_ent, cur_count, cur_sec = (
                    off, end_off, ent, ent, 1, sec
                )

        total_sz = cur_end - cur_start
        mean_ent = round(cur_sum_ent / cur_count, 3)
        assess = self._assess_spike(cur_sec, cur_max_ent, total_sz)
        merged.append(EntropySpike(
            file_offset=cur_start,
            va=self._offset_to_va(cur_start),
            size=total_sz,
            max_entropy=cur_max_ent,
            mean_entropy=mean_ent,
            section_name=cur_sec,
            assessment=assess
        ))

        return merged

    def _assess_spike(self, sec_name: str, max_entropy: float, size: int) -> str:
        """评估高熵块的数据属性"""
        if "text" in sec_name.lower():
            if size > 16384:
                return "高混淆代码段 (疑似 OLLVM 平坦化/强指令替换)"
            else:
                return "代码段异常高熵块 (疑似内联加密数据/Shellcode)"
        elif "data" in sec_name.lower() or "const" in sec_name.lower():
            if size < 8192:
                return "密码学特征块 (疑似白盒加密密钥表 / S-Box / Noise固定密钥)"
            else:
                return "高密度加密数据区 (疑似密文存储 / 压缩资源包)"
        return "高密度未知数据块"
