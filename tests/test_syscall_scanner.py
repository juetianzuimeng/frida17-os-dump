# -*- coding: utf-8 -*-
"""
底层直接系统调用 (Direct Syscall) 探测器单元测试
"""

import unittest
from analyzer.syscall_scanner import SyscallScanner, XNU_SYSCALLS, MACH_TRAPS


class TestSyscallScannerInstructionDecoding(unittest.TestCase):
    """测试 SyscallScanner 的指令解码与系统调用回溯推断能力"""

    def setUp(self):
        self.scanner = SyscallScanner("/dummy/path")

    def test_movz_x16_64bit(self):
        """测试 64 位 MOVZ X16, #imm"""
        # MOVZ X16, #26 (ptrace): 0xD2800350
        # 0xD2800010 | (26 << 5) = 0xD2800010 | 0x340 = 0xD2800350
        word = 0xD2800350
        disasm, val = self.scanner._decode_instruction_simple(word)
        self.assertEqual(val, 26)
        self.assertIn("movz x16", disasm)
        self.assertIn("26", disasm)

    def test_movz_w16_32bit(self):
        """测试 32 位 MOVZ W16, #imm"""
        # MOVZ W16, #202 (sysctl):
        # 0x52800010 | (202 << 5) = 0x52800010 | (0xCA << 5) = 0x52800010 | 0x1940 = 0x52801950
        word = 0x52801950
        disasm, val = self.scanner._decode_instruction_simple(word)
        self.assertEqual(val, 202)
        self.assertIn("movz w16", disasm)
        self.assertIn("202", disasm)

    def test_movn_w16_negative_trap(self):
        """测试 32 位 MOVN W16, #30 (-31, mach_msg_trap)"""
        # MOVN W16, #30:
        # 0x12800010 | (30 << 5) = 0x12800010 | (0x1E << 5) = 0x12800010 | 0x3C0 = 0x128003D0
        word = 0x128003D0
        disasm, val = self.scanner._decode_instruction_simple(word)
        self.assertEqual(val, -31)
        self.assertIn("movn w16", disasm)
        self.assertIn("-31", disasm)

    def test_dynamic_register_transfer(self):
        """测试寄存器间传递 MOV X16, X0"""
        # ORR X16, XZR, X0:
        # 0xAA0003F0 (X16 = X0)
        word = 0xAA0003F0
        disasm, val = self.scanner._decode_instruction_simple(word)
        self.assertIsNone(val)
        self.assertIn("mov x16, x0", disasm)
        self.assertIn("动态传参", disasm)

    def test_resolve_syscall_meta_ptrace(self):
        """测试 ptrace 元数据映射"""
        name, cat, desc, sev = self.scanner._resolve_syscall_meta(svc_imm=0x80, syscall_num=26)
        self.assertEqual(name, "SYS_ptrace")
        self.assertEqual(cat, "Anti-Debug")
        self.assertEqual(sev, "CRITICAL")
        self.assertIn("PT_DENY_ATTACH", desc)

    def test_resolve_syscall_meta_sysctl(self):
        """测试 sysctl 元数据映射"""
        name, cat, desc, sev = self.scanner._resolve_syscall_meta(svc_imm=0x80, syscall_num=202)
        self.assertEqual(name, "SYS___sysctl")
        self.assertEqual(cat, "Anti-Debug")
        self.assertEqual(sev, "CRITICAL")

    def test_resolve_syscall_meta_mach_trap(self):
        """测试 mach_msg_trap 映射"""
        name, cat, desc, sev = self.scanner._resolve_syscall_meta(svc_imm=0x80, syscall_num=-31)
        self.assertEqual(name, "mach_msg_trap")
        self.assertEqual(cat, "MachTrap")

    def test_resolve_syscall_meta_dynamic(self):
        """测试动态计算系统调用映射"""
        name, cat, desc, sev = self.scanner._resolve_syscall_meta(svc_imm=0x80, syscall_num=None)
        self.assertEqual(name, "SYS_DYNAMIC_0x80")
        self.assertEqual(cat, "DynamicSyscall")
        self.assertEqual(sev, "HIGH")

    def test_frida_patch_script_generation(self):
        """测试自动派生 Frida 内存热补丁脚本"""
        from analyzer.syscall_scanner import SyscallItem
        item = SyscallItem(
            va=0x100045678,
            file_offset=0x45678,
            func_va=0x100045600,
            func_offset=0x45600,
            svc_imm=0x80,
            syscall_num=26,
            syscall_name="SYS_ptrace",
            category="Anti-Debug",
            description="PT_DENY_ATTACH",
            severity="CRITICAL",
            context_disasm=["0x100045674: movz x16, #0x1A", "0x100045678: svc #0x80"]
        )
        script = self.scanner.generate_frida_patch_script([item], module_name="TargetApp")
        self.assertIn("TargetApp", script)
        self.assertIn("Memory.protect", script)
        self.assertIn("writeByteArray", script)
        self.assertIn("SYS_ptrace", script)

    def test_end_to_end_macho_syscall_scan(self):
        """测试端到端解析真实构造的 ARM64 Mach-O 二进制并扫描出 SYS_ptrace"""
        import tempfile
        import os
        import struct

        # 构建合法最小 ARM64 Mach-O
        # Mach-O 头部 (32 字节)
        hdr = struct.pack(
            "<7II",
            0xFEEDFACF,          # magic (MH_MAGIC_64)
            0x0100000C,          # cputype (ARM64)
            0x00000000,          # cpusubtype
            0x00000002,          # filetype (MH_EXECUTE)
            1,                   # ncmds (1 个 LC_SEGMENT_64)
            72 + 80,             # sizeofcmds (LC_SEGMENT_64 header 72B + 1 section 80B)
            0x00200000,          # flags (MH_PIE)
            0                    # reserved
        )

        # 指令数据: movz x16, #26 (0xD2800350); svc #0x80 (0xD4001001); ret (0xD65F03C0)
        code_bytes = struct.pack("<3I", 0xD2800350, 0xD4001001, 0xD65F03C0)
        code_file_off = 32 + 72 + 80
        total_file_size = code_file_off + len(code_bytes)

        # LC_SEGMENT_64 (72 字节)
        seg_name = b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        seg = struct.pack(
            "<2I16s4Q4I",
            0x19,                # cmd (LC_SEGMENT_64)
            72 + 80,             # cmdsize
            seg_name,
            0x100000000,         # vmaddr
            0x4000,              # vmsize
            0,                   # fileoff
            total_file_size,     # filesize
            7,                   # maxprot (rwx)
            5,                   # initprot (r-x)
            1,                   # nsects
            0                    # flags
        )

        # Section 64: __TEXT.__text (80 字节)
        sect_name = b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sect = struct.pack(
            "<16s16s2Q8I",
            sect_name,
            seg_name,
            0x100000000 + code_file_off, # addr
            len(code_bytes),             # size
            code_file_off,               # offset
            2,                           # align
            0,                           # reloff
            0,                           # nreloc
            0x80000400,                  # flags
            0, 0, 0                      # reserved1, reserved2, reserved3
        )


        macho_bytes = hdr + seg + sect + code_bytes

        with tempfile.NamedTemporaryFile(suffix="_test_bin", delete=False) as f:
            f.write(macho_bytes)
            tmp_path = f.name

        try:
            scanner = SyscallScanner(tmp_path)
            items = scanner.scan()
            self.assertEqual(len(items), 1)
            item = items[0]
            self.assertEqual(item.svc_imm, 0x80)
            self.assertEqual(item.syscall_num, 26)
            self.assertEqual(item.syscall_name, "SYS_ptrace")
            self.assertEqual(item.severity, "CRITICAL")
            self.assertEqual(item.category, "Anti-Debug")
            self.assertTrue(item.is_anti_debug_or_security)

            # 验证补丁导出
            patch = scanner.generate_frida_patch_script(items)
            self.assertIn("SYS_ptrace", patch)
            self.assertIn("writeByteArray", patch)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()

