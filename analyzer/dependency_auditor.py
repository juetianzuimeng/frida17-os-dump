# -*- coding: utf-8 -*-
"""
动态库依赖拓扑树与导入符号审计器 (Dependency & Import Auditor)

借鉴 REA (Reverse Engineer Anything) 的 ApplicationGraphProjector 机制：
1. 纯 Python 原生解析 Mach-O 的 LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB 与 LC_RPATH；
2. 构建清晰的应用外部依赖拓扑树 (区分系统 Frameworks、私有库、弱依赖与内部 dylib)；
3. 解析 LC_SYMTAB 动态符号表，提取外部导入符号 (Undefined Symbols) 与外部 ObjC 类；
4. 结构化归类关键通信层 API (Network、Crypto、System、Threading)，秒级摸底架构选型。
"""

import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set


# Mach-O 魔数与常量
FAT_MAGIC    = 0xCAFEBABE
FAT_CIGAM    = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
MH_MAGIC_64  = 0xFEEDFACF
MH_CIGAM_64  = 0xCFFAEDFE
MH_MAGIC     = 0xFEEDFACE
MH_CIGAM     = 0xCEFAEDFE
CPU_TYPE_ARM64  = 0x01000000 | 12

LC_SYMTAB           = 0x02
LC_LOAD_DYLIB       = 0x0C
LC_LOAD_WEAK_DYLIB  = 0x18 | 0x80000000
LC_LOAD_WEAK_LEGACY = 0x18
LC_RPATH            = 0x1C | 0x80000000
LC_RPATH_LEGACY     = 0x1C
LC_REEXPORT_DYLIB   = 0x1F


@dataclass
class DylibItem:
    """依赖动态库项"""
    path: str
    link_type: str      # 'LOAD' | 'WEAK' | 'REEXPORT'
    is_system: bool     # 是否系统库 (/System/... 或 /usr/lib/...)

    @property
    def display_name(self) -> str:
        parts = self.path.split("/")
        return parts[-1] if parts else self.path


@dataclass
class DependencyReport:
    """依赖与导入符号全景报表"""
    binary_name: str
    dylibs: List[DylibItem] = field(default_factory=list)
    rpaths: List[str] = field(default_factory=list)
    imported_symbols: List[str] = field(default_factory=list)
    imported_classes: List[str] = field(default_factory=list)
    categorized_apis: Dict[str, List[str]] = field(default_factory=dict)


class DependencyAuditor:
    """动态库依赖拓扑与导入符号解析引擎"""

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self._data: bytes = b""
        self._slice_offset: int = 0
        self._slice_size: int = 0

    def audit(self) -> Optional[DependencyReport]:
        """执行依赖分析并生成报表"""
        if not os.path.isfile(self.file_path):
            return None

        with open(self.file_path, "rb") as f:
            self._data = f.read()

        slice_off, slice_sz = self._select_arm64_slice()
        if slice_off < 0:
            return None
        self._slice_offset = slice_off
        self._slice_size = slice_sz

        return self._parse_mach_o()

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

    def _parse_mach_o(self) -> Optional[DependencyReport]:
        data = self._data
        so = self._slice_offset
        if so + 32 > len(data):
            return None

        le_magic = struct.unpack_from("<I", data, so)[0]
        is_64 = le_magic in (MH_MAGIC_64, MH_CIGAM_64)
        endian = "<" if le_magic in (MH_MAGIC, MH_MAGIC_64) else ">"
        hdr_size = 32 if is_64 else 28

        if is_64:
            _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from(f"{endian}7I", data, so + 4)
        else:
            _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from(f"{endian}6I", data, so + 4)

        cmd_pos = so + hdr_size
        report = DependencyReport(binary_name=os.path.basename(self.file_path))
        symoff, nsyms, stroff, strsize = None, None, None, None

        for _ in range(ncmds):
            if cmd_pos + 8 > len(data): break
            cmd, cmdsize = struct.unpack_from(f"{endian}2I", data, cmd_pos)
            if cmdsize == 0: break

            # 1. 动态库加载命令
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_LOAD_WEAK_LEGACY, LC_REEXPORT_DYLIB):
                link_type = "LOAD"
                if cmd in (LC_LOAD_WEAK_DYLIB, LC_LOAD_WEAK_LEGACY):
                    link_type = "WEAK"
                elif cmd == LC_REEXPORT_DYLIB:
                    link_type = "REEXPORT"

                if cmd_pos + 12 <= len(data):
                    name_off = struct.unpack_from(f"{endian}I", data, cmd_pos + 8)[0]
                    str_start = cmd_pos + name_off
                    str_end = min(cmd_pos + cmdsize, len(data))
                    raw_str = data[str_start:str_end].split(b"\x00")[0].decode("utf-8", errors="replace")
                    is_sys = raw_str.startswith("/System/") or raw_str.startswith("/usr/lib/")
                    report.dylibs.append(DylibItem(path=raw_str, link_type=link_type, is_system=is_sys))

            # 2. RPATH
            elif cmd in (LC_RPATH, LC_RPATH_LEGACY):
                if cmd_pos + 12 <= len(data):
                    name_off = struct.unpack_from(f"{endian}I", data, cmd_pos + 8)[0]
                    str_start = cmd_pos + name_off
                    str_end = min(cmd_pos + cmdsize, len(data))
                    raw_rpath = data[str_start:str_end].split(b"\x00")[0].decode("utf-8", errors="replace")
                    report.rpaths.append(raw_rpath)

            # 3. 符号表
            elif cmd == LC_SYMTAB:
                if cmd_pos + 24 <= len(data):
                    symoff, nsyms, stroff, strsize = struct.unpack_from(f"{endian}4I", data, cmd_pos + 8)

            cmd_pos += cmdsize

        # 4. 解析 Undefined 外部导入符号
        if symoff and nsyms and stroff and strsize:
            abs_symoff = so + symoff
            abs_stroff = so + stroff
            if abs_symoff + nsyms * 16 <= len(data) and abs_stroff + strsize <= len(data):
                str_table = data[abs_stroff : abs_stroff + strsize]
                imported_set: Set[str] = set()
                imported_classes_set: Set[str] = set()

                for i in range(nsyms):
                    n_pos = abs_symoff + i * 16
                    n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(f"{endian}IBBHQ", data, n_pos)
                    # N_UNDF: (n_type & 0x0E) == 0, N_EXT: (n_type & 0x01) == 1
                    if (n_type & 0x0E) == 0 and (n_type & 0x01) != 0 and n_strx > 0:
                        null_idx = str_table.find(b"\x00", n_strx)
                        if null_idx != -1:
                            sym_name = str_table[n_strx:null_idx].decode("utf-8", errors="ignore")
                            if sym_name.startswith("_OBJC_CLASS_$_"):
                                imported_classes_set.add(sym_name[14:])
                            else:
                                clean_name = sym_name.lstrip("_")
                                if clean_name:
                                    imported_set.add(clean_name)

                report.imported_symbols = sorted(imported_set)
                report.imported_classes = sorted(imported_classes_set)

                # 5. 关键业务通信/安全类 API 结构化分类
                cat = {
                    "网络通信 (Networking)": [],
                    "加密与证书 (Crypto & Security)": [],
                    "系统与进程控制 (System & Process)": [],
                    "线程与队列 (Threading & GCD)": []
                }
                for s in report.imported_symbols:
                    s_lower = s.lower()
                    if any(k in s_lower for k in ("socket", "connect", "cfsocket", "nw_", "nsurl", "http", "getaddrinfo", "dns")):
                        cat["网络通信 (Networking)"].append(s)
                    elif any(k in s_lower for k in ("sec", "ssl", "crypto", "aes", "rsa", "sha", "x509", "cc_", "evp")):
                        cat["加密与证书 (Crypto & Security)"].append(s)
                    elif any(k in s_lower for k in ("sysctl", "ptrace", "getenv", "abort", "fork", "task_", "proc_")):
                        cat["系统与进程控制 (System & Process)"].append(s)
                    elif any(k in s_lower for k in ("dispatch_", "pthread_")):
                        cat["线程与队列 (Threading & GCD)"].append(s)

                report.categorized_apis = {k: v for k, v in cat.items() if v}

        return report
