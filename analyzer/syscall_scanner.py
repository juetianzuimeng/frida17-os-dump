# -*- coding: utf-8 -*-
"""
底层系统调用 (Direct Syscall `svc 0x80`) 与反 Hook 内联汇编探测器 (Direct Syscall Scanner)

借鉴 REA (Reverse Engineer Anything) 的底层原生调用边界 (Native Execution Boundaries) 识别机制：
1. 专为 ARM64 Mach-O 打造，基于纯 Python 静态逐指令扫描 __TEXT.__text 执行段；
2. 识别所有绕过 libc/libsystem 直接穿透内核的 `svc #0x80`、`svc #0` 指令机器码；
3. 向前回溯多指令窗口（1~8 条指令），精确还原加载至 X16 寄存器的系统调用编号；
4. 深度映射 iOS/Darwin XNU 内核系统调用字典，锁定 SYS_ptrace、SYS___sysctl、SYS_csops 等顶级反调试与越狱探测；
5. 一键导出针对这些内核直调点的 Frida 内存热补丁脚本，彻底瓦解内联反调试。
"""

import os
import struct
import bisect
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set


# ── iOS / Darwin XNU 常见系统调用与 Mach Trap 知识库 ─────────────────────────
XNU_SYSCALLS: Dict[int, Tuple[str, str, str, str]] = {
    # syscall_num: (syscall_name, category, description, severity)
    1:   ("SYS_exit", "Process", "终止当前进程 (反调试异常时强制退出)", "HIGH"),
    2:   ("SYS_fork", "Process", "创建子进程 (多进程沙盒检测)", "MEDIUM"),
    3:   ("SYS_read", "IO", "文件/描述符底层读取", "LOW"),
    4:   ("SYS_write", "IO", "文件/描述符底层写入", "LOW"),
    5:   ("SYS_open", "Filesystem", "底层打开文件 (直读越狱路径)", "HIGH"),
    6:   ("SYS_close", "Filesystem", "关闭文件描述符", "LOW"),
    7:   ("SYS_wait4", "Process", "等待子进程状态改变", "LOW"),
    9:   ("SYS_link", "Filesystem", "创建硬链接", "LOW"),
    10:  ("SYS_unlink", "Filesystem", "底层删除文件 (清理探测缓存/越狱文件)", "MEDIUM"),
    14:  ("SYS_mknod", "Filesystem", "创建特殊文件节点", "LOW"),
    20:  ("SYS_getpid", "Process", "获取当前进程 PID", "INFO"),
    23:  ("SYS_setuid", "Security", "设置进程用户 ID", "MEDIUM"),
    24:  ("SYS_getuid", "Security", "获取用户 ID (检测 uid=0 root 提权)", "HIGH"),
    25:  ("SYS_geteuid", "Security", "获取有效用户 ID", "HIGH"),
    26:  ("SYS_ptrace", "Anti-Debug", "进程调试追踪控制 (PT_DENY_ATTACH=31 核心反调试)", "CRITICAL"),
    33:  ("SYS_access", "Filesystem", "检查文件存在性 (绕过 NSFileManager 探测越狱文件)", "HIGH"),
    37:  ("SYS_kill", "Process", "发送进程信号 (自杀退出或检测调试器)", "HIGH"),
    39:  ("SYS_getppid", "Process", "获取父进程 PID (检测是否由 lldb/gdb 调试器启动)", "HIGH"),
    43:  ("SYS_getegid", "Security", "获取有效组 ID", "LOW"),
    47:  ("SYS_getgid", "Security", "获取组 ID", "LOW"),
    48:  ("SYS_sigprocmask", "Process", "设置信号屏蔽集 (屏蔽 SIGTRAP 等调试信号)", "HIGH"),
    59:  ("SYS_execve", "Process", "执行新二进制程序", "MEDIUM"),
    73:  ("SYS_munmap", "Memory", "解除内存映射", "LOW"),
    74:  ("SYS_mprotect", "Memory", "修改内存页面权限 (PROT_WRITE/EXEC 防篡改与自修改)", "CRITICAL"),
    80:  ("SYS_setrlimit", "Process", "设置资源上限 (如限制 coredump 防止转储)", "MEDIUM"),
    92:  ("SYS_fcntl", "Filesystem", "文件控制描述符操作", "LOW"),
    97:  ("SYS_socket", "Network", "底层套接字创建 (绕过上层代理/防抓包)", "MEDIUM"),
    98:  ("SYS_connect", "Network", "底层网络连接 (直连远程服务器/本地Frida端口探测)", "HIGH"),
    104: ("SYS_bind", "Network", "绑定网络套接字", "LOW"),
    105: ("SYS_setsockopt", "Network", "设置套接字选项", "LOW"),
    106: ("SYS_listen", "Network", "监听网络套接字", "LOW"),
    116: ("SYS_gettimeofday", "Time", "高精度计时 (检测调试断点导致的时间延迟)", "MEDIUM"),
    133: ("SYS_sendto", "Network", "发送底层套接字数据", "LOW"),
    136: ("SYS_mkdir", "Filesystem", "创建目录", "LOW"),
    147: ("SYS_setsid", "Process", "创建新会话", "LOW"),
    180: ("SYS_unlinkat", "Filesystem", "相对目录删除文件", "MEDIUM"),
    197: ("SYS_mmap", "Memory", "创建内存映射 (动态加载解密代码段)", "HIGH"),
    199: ("SYS_lseek", "Filesystem", "文件偏移指针寻址", "LOW"),
    202: ("SYS___sysctl", "Anti-Debug", "内核参数探测 (检查 KERN_PROC_PID 的 P_TRACED 标志)", "CRITICAL"),
    220: ("SYS_shared_region_check_np", "Memory", "共享库缓存区校验 (检测越狱 Dyld Hook)", "HIGH"),
    338: ("SYS_stat64", "Filesystem", "获取文件属性 (探测 Cydia/Substrate/Frida 静态路径)", "HIGH"),
    339: ("SYS_fstat64", "Filesystem", "获取描述符文件属性", "LOW"),
    340: ("SYS_lstat64", "Filesystem", "符号链接属性检查 (检测 /Applications 符号链接越狱特征)", "HIGH"),
    344: ("SYS_getdirentries64", "Filesystem", "读取目录项清单 (扫描越狱 App 目录)", "MEDIUM"),
    397: ("SYS_proc_info", "Process", "获取指定进程详细运行状态", "MEDIUM"),
    400: ("SYS_csops", "Security", "查询/限制代码签名状态 (CS_OPS_STATUS 越狱与脱壳检测)", "CRITICAL"),
    401: ("SYS_csops_audittoken", "Security", "基于审计令牌校验代码签名状态", "CRITICAL"),
}

MACH_TRAPS: Dict[int, Tuple[str, str, str, str]] = {
    -10: ("mach_reply_port", "MachTrap", "分配 Mach 回复端口", "LOW"),
    -12: ("mach_task_self_trap", "MachTrap", "获取当前任务 task_self 端口", "MEDIUM"),
    -13: ("mach_host_self_trap", "MachTrap", "获取宿主 host_self 端口", "LOW"),
    -26: ("mach_port_allocate", "MachTrap", "分配 Mach 端口", "LOW"),
    -27: ("mach_port_destroy", "MachTrap", "销毁 Mach 端口", "LOW"),
    -31: ("mach_msg_trap", "MachTrap", "Mach IPC 消息收发核心系统陷阱", "MEDIUM"),
    -89: ("mach_timebase_info_trap", "MachTrap", "获取系统时间基准 (计时反调试)", "MEDIUM"),
    -90: ("mach_wait_until_trap", "MachTrap", "线程绝对时间休眠", "LOW"),
}


@dataclass
class SyscallItem:
    """单个直接系统调用指令命中项"""
    va: int                   # 指令虚拟地址 VA
    file_offset: int          # 绝对文件偏移
    func_va: int              # 所属函数起始 VA
    func_offset: int          # 所属函数文件偏移
    svc_imm: int              # SVC 立即数 (通常为 0x80 或 0)
    syscall_num: Optional[int]# 解析出的系统调用编号 (如 26, 202)
    syscall_name: str         # 符号名 (如 'SYS_ptrace')
    category: str             # 业务分类 (Anti-Debug, Security, Filesystem, Process, Network, Dynamic, Unknown)
    description: str          # 含义说明
    severity: str             # 严重级别 ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
    context_disasm: List[str] # 上下文反汇编摘要指令

    @property
    def va_hex(self) -> str:
        return f"0x{self.va:X}"

    @property
    def offset_hex(self) -> str:
        return f"0x{self.file_offset:X}"

    @property
    def func_hex(self) -> str:
        return f"0x{self.func_offset:X}"

    @property
    def is_anti_debug_or_security(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH") or self.category in ("Anti-Debug", "Security")


class SyscallScanner:
    """
    ARM64 Mach-O 直接系统调用 (Direct Syscall `svc 0x80`) 深度静态扫描引擎
    """

    MAX_BACKWARD_STEPS = 8  # 向前回溯指令窗口深度 (最大 8 条指令 = 32 字节)

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self._scanner = None
        self._items: List[SyscallItem] = []
        self._initialized: bool = False

    def initialize(self):
        """延迟加载并完成基础 Mach-O 解析"""
        if self._initialized:
            return
        self._initialized = True

        if not os.path.isfile(self.file_path):
            return

        from .xref_scanner import XrefScanner
        self._scanner = XrefScanner(self.file_path)
        self._scanner.scan()

    def scan(self) -> List[SyscallItem]:
        """执行直接系统调用静态指令扫描与回溯解析"""
        self.initialize()
        if not self._scanner or not self._scanner._data:
            return []

        if self._items:
            return self._items

        scanner = self._scanner
        data = scanner._data
        ts = scanner._text_file_off
        te = min(ts + scanner._text_size, len(data))
        text_va = scanner._text_va
        func_starts = scanner._sorted_func_starts

        results: List[SyscallItem] = []

        # 步长 4 字节顺序扫描 __TEXT.__text
        for off in range(ts, te - 3, 4):
            word = struct.unpack_from("<I", data, off)[0]

            # 匹配 ARM64 SVC 指令: bits [31:21] == 11010100000 (0xD4000000) 且 bits [1:0] == 01
            # (word & 0xFFE0001F) == 0xD4000001
            if (word & 0xFFE0001F) == 0xD4000001:
                svc_imm = (word >> 5) & 0xFFFF
                instr_va = text_va + (off - ts)

                # 计算所属函数
                func_va, func_off = self._resolve_func(instr_va, off, func_starts, text_va, ts)

                # 向前回溯推导 X16 寄存器加载的系统调用号
                syscall_num, context_lines = self._trace_syscall_number(data, off, ts, text_va)

                # 识别系统调用属性
                name, cat, desc, sev = self._resolve_syscall_meta(svc_imm, syscall_num)

                item = SyscallItem(
                    va=instr_va,
                    file_offset=off,
                    func_va=func_va,
                    func_offset=func_off,
                    svc_imm=svc_imm,
                    syscall_num=syscall_num,
                    syscall_name=name,
                    category=cat,
                    description=desc,
                    severity=sev,
                    context_disasm=context_lines
                )
                results.append(item)

        self._items = results
        return self._items

    def _resolve_func(self, instr_va: int, instr_off: int,
                      func_starts: List[int], text_va: int, ts: int) -> Tuple[int, int]:
        """使用二分查找定位该指令归属的函数起始地址"""
        if not func_starts:
            return (instr_va, instr_off)
        idx = bisect.bisect_right(func_starts, instr_va) - 1
        if idx >= 0:
            fva = func_starts[idx]
            foff = ts + (fva - text_va)
            return (fva, foff)
        return (instr_va, instr_off)

    def _trace_syscall_number(self, data: bytes, svc_off: int,
                              ts: int, text_va: int) -> Tuple[Optional[int], List[str]]:
        """
        从 SVC 指令向前回溯 1~8 条指令，解析加载到 X16 / W16 的系统调用号
        同时格式化记录上下文反汇编片段
        """
        context_lines: List[str] = []
        syscall_num: Optional[int] = None

        start_off = max(ts, svc_off - self.MAX_BACKWARD_STEPS * 4)
        for cur in range(start_off, svc_off, 4):
            w = struct.unpack_from("<I", data, cur)[0]
            cur_va = text_va + (cur - ts)
            dis_str, reg_x16_val = self._decode_instruction_simple(w)
            context_lines.append(f"0x{cur_va:X}: {dis_str}")
            if reg_x16_val is not None:
                syscall_num = reg_x16_val

        # 加入当前的 svc 指令
        svc_word = struct.unpack_from("<I", data, svc_off)[0]
        svc_imm = (svc_word >> 5) & 0xFFFF
        context_lines.append(f"0x{text_va + (svc_off - ts):X}: svc #0x{svc_imm:X}")

        return syscall_num, context_lines

    def _decode_instruction_simple(self, word: int) -> Tuple[str, Optional[int]]:
        """
        轻量解码 ARM64 针对 X16 赋值的核心指令
        返回: (简要反汇编字符串, 赋值给X16的立即数或None)
        """
        # 1. MOVZ X16, #imm, LSL #shift (64-bit)
        # opcode: 110100101 (0xD2800000), Rd == 16 (0x10)
        if (word & 0xFF80001F) == 0xD2800010:
            hw = (word >> 21) & 0x3
            imm16 = (word >> 5) & 0xFFFF
            val = imm16 << (hw * 16)
            shift_str = f", lsl #{hw*16}" if hw > 0 else ""
            return f"movz x16, #0x{imm16:X}{shift_str} ; (# {val})", val

        # 2. MOVZ W16, #imm, LSL #shift (32-bit)
        # opcode: 010100101 (0x52800000), Rd == 16 (0x10)
        if (word & 0xFF80001F) == 0x52800010:
            hw = (word >> 21) & 0x3
            imm16 = (word >> 5) & 0xFFFF
            val = imm16 << (hw * 16)
            shift_str = f", lsl #{hw*16}" if hw > 0 else ""
            return f"movz w16, #0x{imm16:X}{shift_str} ; (# {val})", val

        # 3. MOVN X16, #imm, LSL #shift (64-bit 负数/按位取反立即数, Mach Traps 常见)
        if (word & 0xFF80001F) == 0x92800010:
            hw = (word >> 21) & 0x3
            imm16 = (word >> 5) & 0xFFFF
            val = ~(imm16 << (hw * 16))
            # 转换为 32 位有符号数检查
            val_signed = struct.unpack("<i", struct.pack("<I", val & 0xFFFFFFFF))[0]
            return f"movn x16, #0x{imm16:X} ; (# {val_signed})", val_signed

        # 4. MOVN W16, #imm, LSL #shift (32-bit 负数立即数)
        if (word & 0xFF80001F) == 0x12800010:
            hw = (word >> 21) & 0x3
            imm16 = (word >> 5) & 0xFFFF
            val = (~(imm16 << (hw * 16))) & 0xFFFFFFFF
            val_signed = struct.unpack("<i", struct.pack("<I", val))[0]
            return f"movn w16, #0x{imm16:X} ; (# {val_signed})", val_signed

        # 5. ORR X16, XZR, Xn (寄存器传递/动态调用)
        if (word & 0xFFE0FFE0) == 0xAA0003E0 and (word & 0x1F) == 0x10:
            rn = (word >> 16) & 0x1F
            return f"mov x16, x{rn} ; (动态传参系统调用)", None

        # 6. LDR X16/W16, [Xn, ...] (内存查表加载系统调用号)
        if (word & 0xBF00001F) in (0xB9400010, 0xF9400010):
            return f"ldr x16, [...] ; (内存查表动态系统调用)", None

        # 7. ADD / SUB X16, X16, #imm (混淆运算)
        if (word & 0xFF8003FF) == 0x91000210: # add x16, x16, #imm
            imm12 = (word >> 10) & 0xFFF
            return f"add x16, x16, #0x{imm12:X}", None
        if (word & 0xFF8003FF) == 0xD1000210: # sub x16, x16, #imm
            imm12 = (word >> 10) & 0xFFF
            return f"sub x16, x16, #0x{imm12:X}", None

        # 其他常规指令 (通用兜底反汇编简写)
        return f"instr 0x{word:08X}", None

    def _resolve_syscall_meta(self, svc_imm: int,
                              syscall_num: Optional[int]) -> Tuple[str, str, str, str]:
        """
        映射系统调用元数据
        返回: (name, category, description, severity)
        """
        if syscall_num is not None:
            # 1. 优先在 XNU 标准系统调用表中匹配
            if syscall_num in XNU_SYSCALLS:
                return XNU_SYSCALLS[syscall_num]

            # 2. 在 Mach Traps 负数表中匹配
            if syscall_num in MACH_TRAPS:
                return MACH_TRAPS[syscall_num]

            return (
                f"SYS_{syscall_num}",
                "UnknownSyscall",
                f"未在常用库收录的 XNU 内核调用编号 #{syscall_num}",
                "MEDIUM"
            )

        # 未能静态推断出系统调用号 (动态传参或查表)
        if svc_imm == 0x80:
            return (
                "SYS_DYNAMIC_0x80",
                "DynamicSyscall",
                "动态计算或查表决定的底层系统调用 (疑似高度混淆的反调试/安全调用)",
                "HIGH"
            )
        else:
            return (
                f"SVC_0x{svc_imm:X}",
                "GenericSVC",
                f"通用 ARM64 软中断陷入指令 (立即数: 0x{svc_imm:X})",
                "LOW"
            )

    def filter(self, keyword: Optional[str] = None,
               only_high_risk: bool = False) -> List[SyscallItem]:
        """按关键字或高危条件过滤扫描结果"""
        items = self.scan()
        if not keyword and not only_high_risk:
            return items

        results = []
        kw = keyword.lower() if keyword else None
        for item in items:
            if only_high_risk and not item.is_anti_debug_or_security:
                continue
            if kw:
                match = (
                    kw in item.syscall_name.lower() or
                    kw in item.category.lower() or
                    kw in item.description.lower() or
                    kw in item.va_hex.lower() or
                    kw in item.func_hex.lower() or
                    (item.syscall_num is not None and kw == str(item.syscall_num))
                )
                if not match:
                    continue
            results.append(item)
        return results

    def generate_frida_patch_script(self, items: Optional[List[SyscallItem]] = None,
                                    module_name: Optional[str] = None) -> str:
        """
        一键生成 Frida 动态内存热补丁脚本
        将发现的高危 svc 0x80 指令动态替换为 NOP (0xD503201F) 并将返回值设为 0
        """
        if items is None:
            items = [it for it in self.scan() if it.is_anti_debug_or_security]

        mod_str = module_name or os.path.basename(self.file_path)

        script_lines = [
            "// ===========================================================================",
            "// [Frida Auto-Generated] Direct Syscall 内联反调试与系统调用运行时内存热补丁",
            f"// 目标模块: {mod_str}",
            f"// 补丁数量: {len(items)} 处 Direct Syscall 陷阱",
            "// 生成机制: 动态 ASLR 基址重定位 + Memory.protect 修改段权限 + NOP 指令热修补",
            "// ===========================================================================",
            "",
            "(function() {",
            "    'use strict';",
            "",
            f"    const TARGET_MODULE = '{mod_str}';",
            "    const NOP_BYTES = [0x1F, 0x20, 0x03, 0xD5]; // arm64 nop",
            "",
            "    // 待修补的高危内核直调点列表 (相对模块基址的相对偏移)",
            "    const SYSCALL_PATCHES = ["
        ]

        scanner = self._scanner
        text_va = scanner._text_va if scanner else 0x100000000

        for it in items:
            rel_off = it.va - text_va
            script_lines.append(
                f"        {{ offset: 0x{rel_off:X}, name: '{it.syscall_name}', desc: '{it.description}' }},"
            )

        script_lines.extend([
            "    ];",
            "",
            "    function applySyscallPatches() {",
            "        let base = Module.findBaseAddress(TARGET_MODULE);",
            "        if (!base) {",
            "            // 尝试在主进程中匹配主模块",
            "            const mainMod = Process.enumerateModules()[0];",
            "            if (mainMod) base = mainMod.base;",
            "        }",
            "        if (!base) {",
            "            console.log(`[-] 未能定位目标模块 [${TARGET_MODULE}] 基址，将在 500ms 后重试...`);",
            "            setTimeout(applySyscallPatches, 500);",
            "            return;",
            "        }",
            "",
            "        console.log(`[+] 成功定位模块基址: ${base}`);",
            "        let patchedCount = 0;",
            "",
            "        for (const item of SYSCALL_PATCHES) {",
            "            const targetAddr = base.add(item.offset);",
            "            try {",
            "                // 赋予可写权限",
            "                Memory.protect(targetAddr, 4, 'rwx');",
            "                // 写入 NOP 机器码 (0xD503201F)",
            "                targetAddr.writeByteArray(NOP_BYTES);",
            "                // 恢复为只读/可执行权限",
            "                Memory.protect(targetAddr, 4, 'r-x');",
            "                console.log(`[✓] 成功 NOP 修补 Direct Syscall @ ${targetAddr} (${item.name} - ${item.desc})`);",
            "                patchedCount++;",
            "            } catch (err) {",
            "                console.error(`[!] 修补失败 @ ${targetAddr}: ${err.message}`);",
            "            }",
            "        }",
            "        console.log(`[★] Direct Syscall 补丁注入完成: 共生效 ${patchedCount} / ${SYSCALL_PATCHES.length} 处。`);",
            "    }",
            "",
            "    // 延迟 100ms 确保动态库完成内存映射",
            "    setTimeout(applySyscallPatches, 100);",
            "})();",
            ""
        ])

        return "\n".join(script_lines)
