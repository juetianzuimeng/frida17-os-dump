# -*- coding: utf-8 -*-
"""
反调试检测规则库 (Anti-Debugging Rules)
"""

from typing import List, Dict, Any
from .base import RuleCategory, Severity


ANTI_DEBUG_RULES: List[Dict[str, Any]] = [
    {
        "id": "AD-001",
        "category": RuleCategory.ANTI_DEBUG,
        "severity": Severity.CRITICAL,
        "title": "ptrace 系统调用反调试",
        "description": "应用通过导入或调用 ptrace (尤其是 PT_DENY_ATTACH / 31) 阻止 GDB/LLDB 等调试器挂载附加。",
        "remediation": "可使用 Frida Hook `ptrace` 函数并拦截第一个参数为 PT_DENY_ATTACH (31) 的调用直接返回 0；或在动态调试前 Patch 掉二进制中的 ptrace 调用指令。",
        "patterns": {
            "imports": ["_ptrace", "ptrace"],
            "symbols": ["_ptrace", "ptrace", "PT_DENY_ATTACH"],
            "strings": [
                "PT_DENY_ATTACH",
                "ptrace",
                "syscall(SYS_ptrace",
                "SYS_ptrace"
            ],
            "regex": [
                r"\bptrace\s*\(",
                r"PT_DENY_ATTACH",
                r"syscall\s*\(\s*(?:0x1f|31|SYS_ptrace)"
            ]
        }
    },
    {
        "id": "AD-002",
        "category": RuleCategory.ANTI_DEBUG,
        "severity": Severity.CRITICAL,
        "title": "sysctl 进程调试标志检测 (P_TRACED)",
        "description": "应用通过 sysctl 查询当前进程信息结构体 (kinfo_proc)，检查 kp_proc.p_flag 中的 P_TRACED 标志位来判断是否处于被调试状态。",
        "remediation": "使用 Frida Hook `sysctl` 和 `sysctlbyname`，在查询 `CTL_KERN/KERN_PROC/KERN_PROC_PID` 时，将返回结构体中 kp_proc.p_flag 的 P_TRACED (0x00000800) 标志位清零。",
        "patterns": {
            "imports": ["_sysctl", "sysctl", "_sysctlbyname", "sysctlbyname"],
            "symbols": ["_sysctl", "sysctl", "_sysctlbyname", "sysctlbyname"],
            "strings": [
                "kern.proc.pid",
                "kp_proc",
                "p_flag",
                "P_TRACED",
                "kinfo_proc"
            ],
            "regex": [
                r"kern\.proc\.pid",
                r"\bP_TRACED\b",
                r"sysctl\s*\(\s*mib"
            ]
        }
    },
    {
        "id": "AD-003",
        "category": RuleCategory.ANTI_DEBUG,
        "severity": Severity.HIGH,
        "title": "Mach 异常端口监控反调试",
        "description": "应用通过调用 task_get_exception_ports / task_set_exception_ports 替换自身异常处理端口，劫持断点与异常事件，使得外部调试器无法捕获断点信号。",
        "remediation": "通过 Frida Hook `task_set_exception_ports` / `task_swap_exception_ports` 阻止其覆盖宿主断点异常处理端口 (EXC_MASK_BREAKPOINT / EXC_MASK_BAD_ACCESS)。",
        "patterns": {
            "imports": [
                "_task_get_exception_ports",
                "task_get_exception_ports",
                "_task_set_exception_ports",
                "task_set_exception_ports",
                "_task_swap_exception_ports",
                "task_swap_exception_ports"
            ],
            "symbols": [
                "_task_get_exception_ports",
                "task_get_exception_ports",
                "_task_set_exception_ports",
                "task_set_exception_ports"
            ],
            "strings": [
                "task_get_exception_ports",
                "task_set_exception_ports",
                "EXC_MASK_BREAKPOINT",
                "EXC_BREAKPOINT"
            ],
            "regex": [
                r"task_(?:get|set|swap)_exception_ports",
                r"EXC_MASK_BREAKPOINT"
            ]
        }
    },
    {
        "id": "AD-004",
        "category": RuleCategory.ANTI_DEBUG,
        "severity": Severity.HIGH,
        "title": "SIGTRAP / 信号处理器反调试",
        "description": "注册 SIGTRAP / SIGBUS / SIGSEGV 信号捕获函数，通过主动触发断点信号检测是否有调试器拦截，若无调试器则由自身处理程序继续执行，反之触发崩溃。",
        "remediation": "Hook `signal` 和 `sigaction` 函数，过滤对 SIGTRAP (5) 或 SIGILL/SIGBUS 信号的特殊挂钩处理。",
        "patterns": {
            "imports": ["_signal", "signal", "_sigaction", "sigaction"],
            "symbols": ["_signal", "signal", "_sigaction", "sigaction"],
            "strings": [
                "SIGTRAP",
                "sigaction",
                "SIG_IGN",
                "SIG_DFL"
            ],
            "regex": [
                r"signal\s*\(\s*(?:SIGTRAP|5)\s*,",
                r"sigaction\s*\(\s*(?:SIGTRAP|5)\s*,"
            ]
        }
    },
    {
        "id": "AD-005",
        "category": RuleCategory.ANTI_DEBUG,
        "severity": Severity.MEDIUM,
        "title": "getppid 父进程检测反调试",
        "description": "通过 getppid 获取当前父进程 PID，在非调试环境下 iOS 应用的父进程通常为 launchd (PID 1)；若通过 debugserver 或调试代理启动，则父进程 PID 不为 1。",
        "remediation": "Hook `getppid` 函数使其固定返回 1。",
        "patterns": {
            "imports": ["_getppid", "getppid"],
            "symbols": ["_getppid", "getppid"],
            "strings": ["getppid"],
            "regex": [r"\bgetppid\s*\(\s*\)"]
        }
    },
    {
        "id": "AD-006",
        "category": RuleCategory.ANTI_DEBUG,
        "severity": Severity.MEDIUM,
        "title": "DYLD 环境变量注入与调试器探测",
        "description": "检查 DYLD_INSERT_LIBRARIES、DYLD_IMAGE_SUFFIX 或 _dyld_image_count 等动态链接器环境变量，探测是否有调试插件或外部动态库被强制注入。",
        "remediation": "Hook `getenv` 过滤针对 `DYLD_INSERT_LIBRARIES` 等环境变量的查询；或 Hook `_dyld_get_image_name` 隐藏特定调试动态库。",
        "patterns": {
            "strings": [
                "DYLD_INSERT_LIBRARIES",
                "__XPC_DYLD_INSERT_LIBRARIES",
                "DYLD_PRINT_TO_FILE",
                "_dyld_get_image_name",
                "_dyld_image_count",
                "_dyld_get_image_header"
            ],
            "regex": [
                r"DYLD_INSERT_LIBRARIES",
                r"_dyld_(?:get_image_name|image_count|get_image_header)"
            ]
        }
    },
    {
        "id": "AD-007",
        "category": RuleCategory.ANTI_DEBUG,
        "severity": Severity.LOW,
        "title": "终端 tty/isatty 调试探测",
        "description": "通过 isatty(0/1/2) 或 ioctl(TIOCNOTTY) 检测标准输入输出是否重定向到终端设备，辅助判断是否存在 LLDB 交互式调试会话。",
        "remediation": "Hook `isatty` 使其在针对标准文件描述符时返回 0。",
        "patterns": {
            "imports": ["_isatty", "isatty", "_ioctl", "ioctl"],
            "symbols": ["_isatty", "isatty"],
            "strings": ["isatty", "TIOCNOTTY"],
            "regex": [r"\bisatty\s*\("]
        }
    }
]
