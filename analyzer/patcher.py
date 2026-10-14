# -*- coding: utf-8 -*-
"""
ARM64 指令静态热修补与 Frida 内存 Patch 生成器 (Binary & Memory Patcher)

专用于快速绕过反调试、越狱检测、代码校验与强制逻辑分支返回：
1. 静态二进制热修补 (支持 NOP / RET / RET_TRUE / RET_FALSE / 自定义 Hex，带自动备份与新包导出)
2. Frida 动态内存热修补脚本自动生成 (运行时 Memory.protect + Memory.writeByteArray 动态生效)
"""

import os
import shutil
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# 常用 ARM64 补丁机器码模板 (Little-Endian)
PRESET_PATCHES = {
    "NOP": bytes.fromhex("1F 20 03 D5"),                  # nop
    "RET": bytes.fromhex("C0 03 5F D6"),                  # ret
    "RET_TRUE": bytes.fromhex("20 00 80 52 C0 03 5F D6"),  # mov w0, #1; ret
    "RET_FALSE": bytes.fromhex("00 00 80 52 C0 03 5F D6"), # mov w0, #0; ret
}


@dataclass
class PatchItem:
    """单个指令修补项"""
    target_raw: str           # 原始输入目标 (如 '0x1E9B34')
    va: int                   # 虚拟地址 VA
    file_offset: int          # 绝对文件偏移
    action: str               # 动作 (NOP / RET / RET_TRUE / RET_FALSE / HEX)
    original_bytes: bytes     # 原始字节
    patch_bytes: bytes        # 替换的新字节
    description: str          # 动作说明


class BinaryPatcher:
    """ARM64 指令热修补与 Frida 补丁生成引擎"""

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self._data: bytearray = bytearray()
        self._image_base: int = 0
        self._text_va: int = 0
        self._text_file_off: int = 0
        self._text_size: int = 0
        self._initialized: bool = False

    def initialize(self):
        """延迟加载二进制数据与段头"""
        if self._initialized:
            return
        self._initialized = True

        from .xref_scanner import XrefScanner
        scanner = XrefScanner(self.file_path)
        scanner.scan()

        self._data = bytearray(scanner._data)
        self._text_va = scanner._text_va
        self._text_file_off = scanner._text_file_off
        self._text_size = scanner._text_size
        self._image_base = scanner._image_base or 0x100000000

    def parse_patch_spec(self, patch_spec: str) -> Optional[PatchItem]:
        """
        解析补丁表达式: 'Target:Action'
        例如: '0x1E9B34:NOP', '0x1E9B34:RET_TRUE', '0x1E9B34:0x1F2003D5'
        """
        self.initialize()
        if not self._data or ":" not in patch_spec:
            return None

        parts = patch_spec.strip().split(":", 1)
        target_str = parts[0].strip()
        action_str = parts[1].strip().upper()

        # 解析目标地址 (十六进制)
        try:
            target_val = int(target_str, 16) if target_str.lower().startswith("0x") else int(target_str, 16)
        except ValueError:
            return None

        va, file_off = self._normalize_address(target_val)
        if file_off + 4 > len(self._data):
            return None

        # 匹配补丁字节
        patch_bytes = b""
        desc = ""
        if action_str in PRESET_PATCHES:
            patch_bytes = PRESET_PATCHES[action_str]
            desc = f"预设指令: {action_str}"
        else:
            # 尝试作为纯十六进制机器码解析 (如 '1F2003D5' 或 '0x1F2003D5')
            hex_clean = action_str.replace("0X", "").replace(" ", "")
            try:
                patch_bytes = bytes.fromhex(hex_clean)
                desc = f"自定义机器码: {patch_bytes.hex().upper()}"
            except ValueError:
                return None

        orig_bytes = bytes(self._data[file_off : file_off + len(patch_bytes)])

        return PatchItem(
            target_raw=target_str,
            va=va,
            file_offset=file_off,
            action=action_str,
            original_bytes=orig_bytes,
            patch_bytes=patch_bytes,
            description=desc
        )

    def apply_patch(
        self,
        patches: List[PatchItem],
        output_path: Optional[str] = None,
        create_backup: bool = True
    ) -> Tuple[str, List[PatchItem]]:
        """
        将补丁应用到文件。若 output_path 未指定，则创建 .patched 文件。
        返回: (最终输出文件路径, 成功应用的 PatchItem 列表)
        """
        self.initialize()
        out_file = output_path or f"{self.file_path}.patched"
        out_file = os.path.abspath(out_file)

        # 自动备份原始文件
        if create_backup and not os.path.exists(f"{self.file_path}.bak"):
            shutil.copy2(self.file_path, f"{self.file_path}.bak")

        # 在副本内存中执行打补丁
        data_copy = bytearray(self._data)
        applied = []

        for p in patches:
            foff = p.file_offset
            plen = len(p.patch_bytes)
            if foff + plen <= len(data_copy):
                data_copy[foff : foff + plen] = p.patch_bytes
                applied.append(p)

        # 写出新文件并赋予可执行权限
        os.makedirs(os.path.dirname(out_file), exist_ok=True) if os.path.dirname(out_file) else None
        with open(out_file, "wb") as f:
            f.write(data_copy)
        try:
            os.chmod(out_file, 0o755)
        except Exception:
            pass

        return (out_file, applied)

    def generate_frida_patch_script(
        self,
        module_name: str,
        patches: List[PatchItem]
    ) -> str:
        """
        根据补丁项自动生成无需修改原二进制文件的 Frida 内存热修补脚本。
        运行时通过 Memory.protect 修改代码段写权限并写入字节。
        """
        self.initialize()
        snippets = []

        for p in patches:
            rva = p.va - self._image_base if p.va >= self._image_base else p.va
            rva_hex = hex(rva)
            patch_hex_str = ", ".join(f"0x{b:02x}" for b in p.patch_bytes)
            orig_hex_str = ", ".join(f"0x{b:02x}" for b in p.original_bytes)
            byte_len = len(p.patch_bytes)

            snippet = f"""
    // ------------------------------------------------------------------------
    // Patch: {p.target_raw} -> {p.action} ({p.description})
    // ------------------------------------------------------------------------
    (function() {{
        const targetOffset = ptr("{rva_hex}");
        const targetAddress = base.add(targetOffset);
        const patchBytes = [{patch_hex_str}];
        const byteLen = {byte_len};

        try {{
            // 1. 修改内存为可读可写可执行 (rwx)
            Memory.protect(targetAddress, byteLen, 'rwx');

            // 2. 写入热补丁字节
            targetAddress.writeByteArray(patchBytes);

            // 3. 恢复内存保护为只读可执行 (r-x)
            Memory.protect(targetAddress, byteLen, 'r-x');

            console.log("[+] 热补丁成功应用: {p.target_raw} ({p.action}) @ " + targetAddress);
        }} catch (e) {{
            console.error("[-] 热补丁应用失败: {p.target_raw} -> " + e.message);
        }}
    }})();
"""
            snippets.append(snippet)

        script = f"""/**
 * ============================================================================
 * Frida Dynamic Memory Patch Script - 运行时内存热补丁
 * 生成源: frida-ios-dump 逆向分析引擎
 * 目标模块: {module_name}
 * 包含热补丁数: {len(patches)} 处
 * 使用命令: frida -U -f <BundleID> -l this_script.js --no-pause
 * ============================================================================
 */

(function() {{
    'use strict';

    const MODULE_NAME = "{module_name}";
    const mod = Process.findModuleByName(MODULE_NAME) || Process.enumerateModules()[0];
    if (!mod) {{
        console.error("[-] 未能定位目标模块: " + MODULE_NAME);
        return;
    }}
    const base = mod.base;
    console.log("[*] 成功锁定目标模块: " + mod.name + " (Base: " + base + ")");

    // ------------------------------------------------------------------------
    // 执行内存热补丁
    // ------------------------------------------------------------------------
    {''.join(snippets)}

    console.log("[*] 所有运行时内存热补丁已生效，继续执行目标业务逻辑...\\n");
}})();
"""
        return script

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
