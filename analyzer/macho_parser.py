# -*- coding: utf-8 -*-
"""
Mach-O 二进制文件解析器
支持解析 Fat Universal 二进制与单架构 Mach-O (ARM64, ARM64e, x86_64)，提取：
- 加密状态 (Cryptid / 砸壳判定)
- 编译加固属性 (PIE, Stack Canary, ARC)
- 导入导出符号 (Imports & Exports)
- 动态链接库列表 (LC_LOAD_DYLIB)
- 文本与数据段字符串 (CString, ObjC Selectors, Const Strings)
"""

import os
import re
import struct
import subprocess
from typing import List, Set, Dict, Any, Tuple, Optional
from .rules.base import TargetBinaryInfo


# Mach-O Magic 常量
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

# Mach-O CPU Type 常量
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x01000000 | 12
CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = 0x01000000 | 7

# Mach-O Header Flags
MH_PIE = 0x00200000

# Mach-O Load Command 常量
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
LC_RPATH = 0x1C | 0x80000000
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C


class MachOParser:
    """Mach-O 二进制静态解析引擎"""

    def __init__(self, file_path: str, rel_path: str = "", is_main: bool = False, is_framework: bool = False, is_plugin: bool = False):
        self.file_path = file_path
        self.rel_path = rel_path or os.path.basename(file_path)
        self.is_main = is_main
        self.is_framework = is_framework
        self.is_plugin = is_plugin

    def parse(self) -> TargetBinaryInfo:
        """完整解析 Mach-O 目标并返回 TargetBinaryInfo"""
        binary_info = TargetBinaryInfo(
            name=os.path.basename(self.file_path),
            rel_path=self.rel_path,
            abs_path=self.file_path,
            is_main=self.is_main,
            is_framework=self.is_framework,
            is_plugin=self.is_plugin
        )

        if not os.path.isfile(self.file_path):
            return binary_info

        try:
            # 1. 结构化二进制解析（Header, Load Commands, Cryptid, PIE, Dylibs, Symbols）
            self._parse_macho_headers_and_commands(binary_info)
        except Exception as e:
            # 二进制解析容错
            pass

        # 2. 提取文本字符串（结合系统 strings 与原生提取）
        extracted_strings = self._extract_strings()
        binary_info.strings = extracted_strings
        binary_info.text_content = "\n".join(extracted_strings)

        # 3. 提取外部导入/导出符号（结合 nm 工具与内置解析）
        self._extract_symbols_via_tool(binary_info)

        # 4. 判断 Stack Canary 和 ARC
        self._check_compiler_protections(binary_info)

        return binary_info

    def _parse_macho_headers_and_commands(self, info: TargetBinaryInfo):
        """解析 Mach-O 文件头与加载命令"""
        with open(self.file_path, "rb") as f:
            header_bytes = f.read(4)
            if len(header_bytes) < 4:
                return

            magic = struct.unpack(">I", header_bytes)[0]
            f.seek(0)

            slices: List[Tuple[int, int]] = []  # (offset, size)

            if magic in (FAT_MAGIC, FAT_CIGAM):
                endian = ">" if magic == FAT_MAGIC else "<"
                f.seek(4)
                nfat_arch = struct.unpack(f"{endian}I", f.read(4))[0]
                for _ in range(nfat_arch):
                    cputype, cpusubtype, offset, size, align = struct.unpack(f"{endian}5I", f.read(20))
                    arch_name = self._cputype_to_str(cputype, cpusubtype)
                    if arch_name not in info.archs:
                        info.archs.append(arch_name)
                    slices.append((offset, size))
            elif magic in (FAT_MAGIC_64, FAT_CIGAM_64):
                endian = ">" if magic == FAT_MAGIC_64 else "<"
                f.seek(4)
                nfat_arch = struct.unpack(f"{endian}I", f.read(4))[0]
                for _ in range(nfat_arch):
                    cputype, cpusubtype, offset, size, align = struct.unpack(f"{endian}2I2QI", f.read(32))
                    arch_name = self._cputype_to_str(cputype, cpusubtype)
                    if arch_name not in info.archs:
                        info.archs.append(arch_name)
                    slices.append((offset, size))
            else:
                # 单架构 Mach-O
                slices.append((0, os.path.getsize(self.file_path)))

            # 解析主要架构切片（优先解析 ARM64 或首个切片）
            for offset, size in slices:
                f.seek(offset)
                slice_magic_bytes = f.read(4)
                if len(slice_magic_bytes) < 4:
                    continue
                slice_magic = struct.unpack("<I", slice_magic_bytes)[0]
                is_64 = slice_magic in (MH_MAGIC_64, MH_CIGAM_64)
                endian = "<" if slice_magic in (MH_MAGIC, MH_MAGIC_64) else ">"

                f.seek(offset + 4)
                if is_64:
                    hdr_data = f.read(28)
                    if len(hdr_data) < 28:
                        continue
                    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(
                        f"{endian}7I", hdr_data
                    )
                else:
                    hdr_data = f.read(24)
                    if len(hdr_data) < 24:
                        continue
                    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
                        f"{endian}6I", hdr_data
                    )

                arch_str = self._cputype_to_str(cputype, cpusubtype)
                if arch_str not in info.archs:
                    info.archs.append(arch_str)

                # 检查 PIE
                if flags & MH_PIE:
                    info.has_pie = True

                # 遍历 Load Commands
                cmd_offset = offset + (32 if is_64 else 28)
                for _ in range(ncmds):
                    f.seek(cmd_offset)
                    cmd_hdr = f.read(8)
                    if len(cmd_hdr) < 8:
                        break
                    cmd, cmdsize = struct.unpack(f"{endian}2I", cmd_hdr)
                    if cmdsize == 0:
                        break

                    # 1. 检查加密状态 (LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64)
                    if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                        f.seek(cmd_offset + 8)
                        enc_data = f.read(12)
                        if len(enc_data) >= 12:
                            cryptoff, cryptsize, cryptid = struct.unpack(f"{endian}3I", enc_data[:12])
                            info.cryptid = cryptid
                            if cryptid != 0:
                                info.is_encrypted = True

                    # 2. 检查依赖动态库 (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB)
                    elif cmd & 0x7FFFFFFF in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, 0x1F):
                        f.seek(cmd_offset + 8)
                        # dylib_command 结构: dylib.name offset(4), timestamp(4), current_version(4), compatibility_version(4)
                        dylib_data = f.read(cmdsize - 8)
                        if len(dylib_data) >= 16:
                            str_offset = struct.unpack(f"{endian}I", dylib_data[:4])[0]
                            if str_offset < cmdsize:
                                raw_str = dylib_data[str_offset - 8:]
                                null_idx = raw_str.find(b"\x00")
                                if null_idx != -1:
                                    dylib_path = raw_str[:null_idx].decode("utf-8", errors="ignore")
                                    if dylib_path and dylib_path not in info.dylibs:
                                        info.dylibs.append(dylib_path)

                    # 3. 检查 RPATH (LC_RPATH)
                    elif cmd & 0x7FFFFFFF == (LC_RPATH & 0x7FFFFFFF):
                        info.has_rpath = True

                    cmd_offset += cmdsize

    def _extract_strings(self) -> Set[str]:
        """提取二进制中的 ASCII 与 UTF-8 字符串"""
        res_strings: Set[str] = set()

        # 优先使用系统 strings 工具以极快速度获取
        try:
            cmd = ["/usr/bin/strings", "-a", "-n", "4", self.file_path]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore", timeout=30)
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    cleaned = line.strip()
                    if 3 <= len(cleaned) <= 300:
                        res_strings.add(cleaned)
                if len(res_strings) > 50:
                    return res_strings
        except Exception:
            pass

        # 纯 Python 备用提取器
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
            # 匹配 4 个及以上可打印字符
            ascii_matches = re.findall(rb"[\x20-\x7E]{4,}", data)
            for m in ascii_matches:
                try:
                    s = m.decode("ascii", errors="ignore").strip()
                    if 3 <= len(s) <= 300:
                        res_strings.add(s)
                except Exception:
                    continue
        except Exception:
            pass

        return res_strings

    def _extract_symbols_via_tool(self, info: TargetBinaryInfo):
        """调用 nm / otool 提取导入与导出符号"""
        try:
            # 提取未定义/外部导入符号 (nm -u)
            proc_u = subprocess.run(
                ["/usr/bin/nm", "-u", self.file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="ignore",
                timeout=20
            )
            if proc_u.returncode == 0:
                for line in proc_u.stdout.splitlines():
                    parts = line.strip().split()
                    if parts:
                        sym = parts[-1]
                        info.imports.add(sym)
                        # 去除开头的下划线存一份
                        if sym.startswith("_"):
                            info.imports.add(sym[1:])

            # 提取已定义符号/导出符号 (nm -gU)
            proc_g = subprocess.run(
                ["/usr/bin/nm", "-gU", self.file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="ignore",
                timeout=20
            )
            if proc_g.returncode == 0:
                for line in proc_g.stdout.splitlines():
                    parts = line.strip().split()
                    if parts:
                        sym = parts[-1]
                        info.exports.add(sym)
                        if sym.startswith("_"):
                            info.exports.add(sym[1:])
        except Exception:
            pass

    def _check_compiler_protections(self, info: TargetBinaryInfo):
        """检查 Stack Canary 和 ARC"""
        # Stack Canary
        canary_symbols = {"___stack_chk_guard", "___stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail"}
        if any(s in info.imports or s in info.strings for s in canary_symbols):
            info.has_canary = True

        # ARC
        arc_symbols = {"_objc_release", "_objc_retain", "_objc_autoreleaseReturnValue", "_objc_storeStrong"}
        if any(s in info.imports or s in info.strings for s in arc_symbols):
            info.has_arc = True

    @staticmethod
    def _cputype_to_str(cputype: int, cpusubtype: int) -> str:
        if cputype == CPU_TYPE_ARM64:
            if (cpusubtype & 0x00FFFFFF) == 2:
                return "arm64e"
            return "arm64"
        elif cputype == CPU_TYPE_ARM:
            return "armv7"
        elif cputype == CPU_TYPE_X86_64:
            return "x86_64"
        elif cputype == CPU_TYPE_X86:
            return "i386"
        return f"cpu_{cputype}"
