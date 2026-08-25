# -*- coding: utf-8 -*-
"""
Frida 与动态 Hook 工具检测规则库 (Frida & Hook Detection Rules)
覆盖 Frida 端口、FridaGadget/Agent、线程名检测、Fishhook、Dobby、CydiaSubstrate 等常见 Hook 框架
"""

from typing import List, Dict, Any
from .base import RuleCategory, Severity


FRIDA_HOOK_RULES: List[Dict[str, Any]] = [
    {
        "id": "FH-001",
        "category": RuleCategory.FRIDA_HOOK,
        "severity": Severity.CRITICAL,
        "title": "Frida 默认服务端口扫描 (27042/27043/23924/23946)",
        "description": "应用在后台线程尝试向本地 127.0.0.1 的 27042 (Frida默认)、27043、23924、23946 等端口发起 socket connect 连接，以探测是否存在正在运行的 frida-server。",
        "remediation": "启动 frida-server 时自定义监听端口（如 `frida-server -l 0.0.0.0:19999`），或通过 Frida Hook `connect` / `getaddrinfo` 函数过滤针对本地这几个特征端口的探测尝试。",
        "patterns": {
            "strings": [
                "27042",
                "27043",
                "23924",
                "23946",
                "127.0.0.1",
                "localhost",
                "frida-server"
            ],
            "regex": [
                r"\b(?:27042|27043|23924|23946)\b",
                r"127\.0\.0\.1:(?:27042|27043|23924)"
            ]
        }
    },
    {
        "id": "FH-002",
        "category": RuleCategory.FRIDA_HOOK,
        "severity": Severity.CRITICAL,
        "title": "Frida 特征动态库与模块引用 (FridaGadget / frida-agent)",
        "description": "应用检查当前进程内存空间或文件系统中是否存在 Frida 核心动态库（FridaGadget.dylib、frida-agent.dylib、libfrida 等）。",
        "remediation": "重命名 FridaGadget.dylib 为无害名称，并去除/修改其中的 Frida 导出符号；或者 Hook `_dyld_get_image_name` 与 `dlopen` 抹除相关名称。",
        "patterns": {
            "strings": [
                "FridaGadget",
                "FridaGadget.dylib",
                "frida-agent",
                "frida-agent.dylib",
                "libfrida",
                "frida-server",
                "frida:rpc",
                "gum-js-loop"
            ],
            "regex": [
                r"FridaGadget(?:\.dylib)?",
                r"frida-agent(?:\.dylib)?",
                r"frida:rpc",
                r"gum-js-loop"
            ]
        }
    },
    {
        "id": "FH-003",
        "category": RuleCategory.FRIDA_HOOK,
        "severity": Severity.HIGH,
        "title": "Frida 运行时线程名与环境特征检测",
        "description": "应用遍历当前进程所有运行线程，调用 pthread_getname_np 检查是否存在以 'gum-js-loop'、'gmain'、'pool-frida'、'frida-' 开头的特征工作线程。",
        "remediation": "使用 Frida 脚本在初始化时通过 `pthread_setname_np` 重命名 Frida 的内部工作线程，或 Hook `pthread_getname_np` 过滤这些线程特征。",
        "patterns": {
            "strings": [
                "gum-js-loop",
                "gmain",
                "pool-frida",
                "frida-worker",
                "pthread_getname_np"
            ],
            "regex": [
                r"gum-js-loop",
                r"pool-frida",
                r"pthread_getname_np"
            ]
        }
    },
    {
        "id": "FH-004",
        "category": RuleCategory.FRIDA_HOOK,
        "severity": Severity.HIGH,
        "title": "Fishhook (C符号动态重绑定) 框架特征",
        "description": "应用内置了 Fishhook 框架（rebind_symbols, rebind_symbols_image, rebinding），可能用于反 Hook（自我防护重绑定）或动态替换系统 C 符号。",
        "remediation": "分析应用调用 `rebind_symbols` 的逻辑，防止其将已 Hook 的函数指针还原覆盖；或对 `rebind_symbols` 进行插桩监控。",
        "patterns": {
            "symbols": [
                "rebind_symbols",
                "_rebind_symbols",
                "rebind_symbols_image",
                "_rebind_symbols_image"
            ],
            "strings": [
                "rebind_symbols",
                "rebind_symbols_image",
                "struct rebinding",
                "fishhook"
            ],
            "regex": [
                r"\brebind_symbols(?:_image)?\b",
                r"struct\s+rebinding"
            ]
        }
    },
    {
        "id": "FH-005",
        "category": RuleCategory.FRIDA_HOOK,
        "severity": Severity.HIGH,
        "title": "Dobby / CydiaSubstrate Inline Hook 引擎集成",
        "description": "应用内嵌了 Dobby 或 CydiaSubstrate 等底层内联指令 Hook 库，可能用于内部函数拦截或运行时安全加固探针。",
        "remediation": "检查应用内 Dobby / Substrate 的 Hook 目的，若为加固防御探针可对其 Hook 注册入口直接屏蔽。",
        "patterns": {
            "symbols": [
                "DobbyHook",
                "dobby_enable",
                "dobby_disable",
                "MSHookFunction",
                "MSHookMessageEx",
                "MSFindSymbol"
            ],
            "strings": [
                "DobbyHook",
                "dobby_hook",
                "MSHookFunction",
                "MSHookMessageEx",
                "CydiaSubstrate",
                "libsubstrate.dylib"
            ],
            "regex": [
                r"\bDobbyHook\b",
                r"MSHookFunction",
                r"MSHookMessageEx"
            ]
        }
    },
    {
        "id": "FH-006",
        "category": RuleCategory.FRIDA_HOOK,
        "severity": Severity.MEDIUM,
        "title": "代码段完整性与指令篡改校验 (__TEXT Section Integrity)",
        "description": "应用在运行时计算 __TEXT / __text 代码段的 CRC32 / SHA256 哈希值，或者检查函数入口指令是否被替换为 B/BL/SVC/BRK 等跳转指令（检测是否遭遇 Inline Hook）。",
        "remediation": "定位其内存校验的基准哈希或校验函数，在校验逻辑处直接 Hook 统一返回原始校验值或绕过检测分支。",
        "patterns": {
            "strings": [
                "__TEXT",
                "__text",
                "mach_header",
                "_dyld_get_image_header",
                "mach_vm_region",
                "mach_vm_read",
                "vm_protect"
            ],
            "regex": [
                r"__TEXT\s*,\s*__text",
                r"mach_vm_region",
                r"_dyld_get_image_header"
            ]
        }
    }
]
