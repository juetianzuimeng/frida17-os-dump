# -*- coding: utf-8 -*-
"""
结构化字符串与 CoreFoundation 常量字典提取器 (Structured String Extractor)

借鉴 REA (Reverse Engineer Anything) 的结构化 StringTableInspector 机制：
1. 解析 __DATA / __DATA_CONST 中的 __cfstring 结构体 (支持 arm64e PAC 掩码过滤)；
2. 解析 __TEXT.__ustring 中的 UTF-16 LE 宽字符字符串 (捕获 Emoji 与现代宽字符日志)；
3. 解析 __TEXT.__cstring 中的常规 C 字符串；
4. 输出带虚拟地址 (VA)、物理偏移、类型与长度的干净结构化字典，
   可直接作为线索无缝喂给 XrefScanner (--xrefs) 定位引用函数。
"""

import os
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# Mach-O 魔数定义
FAT_MAGIC    = 0xCAFEBABE
FAT_CIGAM    = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
MH_MAGIC_64  = 0xFEEDFACF
MH_CIGAM_64  = 0xCFFAEDFE
MH_MAGIC     = 0xFEEDFACE
MH_CIGAM     = 0xCEFAEDFE
CPU_TYPE_ARM64  = 0x01000000 | 12


@dataclass
class StringItem:
    """单个结构化字符串项"""
    va: int              # 虚拟地址 VA
    file_offset: int     # 绝对文件偏移
    str_type: str        # 'CFString' | 'UString' | 'CString'
    length: int          # 字符数
    value: str           # 文本内容
    section: str         # 所属节名 (如 '__DATA_CONST.__cfstring')

    @property
    def va_hex(self) -> str:
        return f"0x{self.va:X}"

    @property
    def offset_hex(self) -> str:
        return f"0x{self.file_offset:X}"


class StringExtractor:
    """Mach-O 结构化字符串与 CFString 提取引擎"""

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self._data: bytes = b""
        self._slice_offset: int = 0
        self._slice_size: int = 0
        self._sections: List[Dict] = []
        self._initialized: bool = False

    def initialize(self):
        """延迟加载并解析段节表"""
        if self._initialized:
            return
        self._initialized = True

        if not os.path.isfile(self.file_path):
            return

        with open(self.file_path, "rb") as f:
            self._data = f.read()

        slice_off, slice_sz = self._select_arm64_slice()
        if slice_off < 0:
            return
        self._slice_offset = slice_off
        self._slice_size = slice_sz
        self._parse_sections()

    def _select_arm64_slice(self) -> Tuple[int, int]:
        """定位 Mach-O arm64/arm64e 切片"""
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
        """解析所有 Mach-O Section 建立 VA -> FileOffset 映射"""
        data = self._data
        so = self._slice_offset
        if so + 8 > len(data):
            return

        le_magic = struct.unpack_from("<I", data, so)[0]
        is_64 = le_magic in (MH_MAGIC_64, MH_CIGAM_64)
        endian = "<" if le_magic in (MH_MAGIC, MH_MAGIC_64) else ">"
        hdr_size = 32 if is_64 else 28
        if so + hdr_size > len(data):
            return

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
                            "seg": s_seg,
                            "sect": s_name,
                            "va": s_va,
                            "size": s_vmsz,
                            "file_off": so + s_off,
                            "key": f"{s_seg},{s_name}"
                        })
                        sect_pos += sect_size

            cmd_pos += cmdsize

    def va_to_file_offset(self, va: int) -> Optional[int]:
        """将 VA 转换为文件绝对偏移，自动兼容 ARM64 PAC / Chained Fixups 掩码"""
        # 1. 尝试 32/36 位掩码（去除 arm64e PAC/Chained 指针高位 Tag）
        clean_va = va & 0xFFFFFFFF
        for s in self._sections:
            if s["va"] <= clean_va < s["va"] + s["size"]:
                return s["file_off"] + (clean_va - s["va"])

        # 2. 尝试标准 64 位直接比对
        for s in self._sections:
            if s["va"] <= va < s["va"] + s["size"]:
                return s["file_off"] + (va - s["va"])

        # 3. 尝试去除最高 16 位 (部分 48-bit VA 平台)
        mask_48 = va & 0xFFFFFFFFFFFF
        for s in self._sections:
            if s["va"] <= mask_48 < s["va"] + s["size"]:
                return s["file_off"] + (mask_48 - s["va"])

        return None

    def extract_cfstrings(self, min_len: int = 1, keyword: Optional[str] = None) -> List[StringItem]:
        """解析 __DATA / __DATA_CONST.__cfstring 结构体"""
        self.initialize()
        results: List[StringItem] = []
        kw_lower = keyword.lower() if keyword else None

        cf_sects = [s for s in self._sections if s["sect"] == "__cfstring"]
        data = self._data

        for s in cf_sects:
            count = s["size"] // 32
            base_off = s["file_off"]
            base_va = s["va"]

            for i in range(count):
                item_off = base_off + i * 32
                item_va = base_va + i * 32
                if item_off + 32 > len(data): break

                isa, flags, cstr_va, length = struct.unpack_from("<4Q", data, item_off)
                if length < min_len:
                    continue

                # 映射并读取字符串字节
                target_off = self.va_to_file_offset(cstr_va)
                if target_off is None or target_off >= len(data):
                    continue

                raw_bytes = data[target_off : target_off + length]
                try:
                    val = raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    # 尝试 UTF-16
                    try:
                        raw_16 = data[target_off : target_off + length * 2]
                        val = raw_16.decode("utf-16-le")
                    except Exception:
                        val = raw_bytes.decode("latin-1", errors="replace")

                if kw_lower and kw_lower not in val.lower():
                    continue

                results.append(StringItem(
                    va=item_va,
                    file_offset=item_off,
                    str_type="CFString",
                    length=len(val),
                    value=val,
                    section=f"{s['seg']}.{s['sect']}"
                ))

        return results

    def extract_ustrings(self, min_len: int = 1, keyword: Optional[str] = None) -> List[StringItem]:
        """解析 __TEXT.__ustring (UTF-16 LE 宽字符)"""
        self.initialize()
        results: List[StringItem] = []
        kw_lower = keyword.lower() if keyword else None

        u_sects = [s for s in self._sections if s["sect"] == "__ustring"]
        data = self._data

        for s in u_sects:
            sect_data = data[s["file_off"] : s["file_off"] + s["size"]]
            # 以 \x00\x00 双零截断切分 UTF-16 LE
            cur_pos = 0
            while cur_pos < len(sect_data):
                # 寻找 UTF-16 \x00\x00 结尾
                end = cur_pos
                while end + 1 < len(sect_data):
                    if sect_data[end] == 0 and sect_data[end + 1] == 0:
                        break
                    end += 2

                raw_chunk = sect_data[cur_pos:end]
                if raw_chunk:
                    try:
                        val = raw_chunk.decode("utf-16-le").strip()
                        if len(val) >= min_len:
                            if not kw_lower or kw_lower in val.lower():
                                results.append(StringItem(
                                    va=s["va"] + cur_pos,
                                    file_offset=s["file_off"] + cur_pos,
                                    str_type="UString",
                                    length=len(val),
                                    value=val,
                                    section=f"{s['seg']}.{s['sect']}"
                                ))
                    except Exception:
                        pass
                cur_pos = end + 2

        return results

    def extract_cstrings(self, min_len: int = 3, keyword: Optional[str] = None) -> List[StringItem]:
        """解析 __TEXT.__cstring (常规以 null 结尾的 C 字符串)"""
        self.initialize()
        results: List[StringItem] = []
        kw_lower = keyword.lower() if keyword else None

        c_sects = [s for s in self._sections if s["sect"] == "__cstring"]
        data = self._data

        for s in c_sects:
            sect_data = data[s["file_off"] : s["file_off"] + s["size"]]
            # 顺序扫描 \x00 分隔
            start = 0
            while start < len(sect_data):
                null_idx = sect_data.find(b"\x00", start)
                if null_idx == -1:
                    null_idx = len(sect_data)
                raw_chunk = sect_data[start:null_idx]
                if len(raw_chunk) >= min_len:
                    try:
                        val = raw_chunk.decode("utf-8")
                        if not kw_lower or kw_lower in val.lower():
                            results.append(StringItem(
                                va=s["va"] + start,
                                file_offset=s["file_off"] + start,
                                str_type="CString",
                                length=len(val),
                                value=val,
                                section=f"{s['seg']}.{s['sect']}"
                            ))
                    except UnicodeDecodeError:
                        pass
                start = null_idx + 1

        return results

    def extract_all(
        self,
        min_len: int = 3,
        keyword: Optional[str] = None,
        string_type: str = "all"
    ) -> List[StringItem]:
        """全量或按类型提取结构化字符串"""
        self.initialize()
        st = string_type.lower()
        items: List[StringItem] = []

        if st in ("all", "cfstring"):
            items.extend(self.extract_cfstrings(min_len=min_len, keyword=keyword))
        if st in ("all", "ustring"):
            items.extend(self.extract_ustrings(min_len=min_len, keyword=keyword))
        if st in ("all", "cstring"):
            items.extend(self.extract_cstrings(min_len=min_len, keyword=keyword))

        # 按 VA 升序排序
        items.sort(key=lambda x: x.va)
        return items
