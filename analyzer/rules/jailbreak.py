# -*- coding: utf-8 -*-
"""
越狱检测规则库 (Jailbreak Detection Rules)
覆盖传统越狱 (Rootful) 与现代无根越狱 (Rootless / Dopamine / Palera1n / XinaA15 等)
"""

from typing import List, Dict, Any
from .base import RuleCategory, Severity


JAILBREAK_RULES: List[Dict[str, Any]] = [
    {
        "id": "JB-001",
        "category": RuleCategory.JAILBREAK,
        "severity": Severity.HIGH,
        "title": "典型越狱文件/目录路径探测 (Rootful & Rootless)",
        "description": "应用通过 stat/access/fopen/NSFileManager 检查常见越狱文件（如 Cydia、Sileo、Zebra、Filza、MobileSubstrate、/var/jb/ 等）是否存在。",
        "remediation": "使用 Frida Hook `stat`, `lstat`, `access`, `open`, `fopen`, `access` 及 `-[NSFileManager fileExistsAtPath:]`，将越狱相关路径请求拦截并伪装返回文件不存在 (ENOENT / NO)。",
        "patterns": {
            "strings": [
                "/Applications/Cydia.app",
                "/Applications/Sileo.app",
                "/Applications/Zebra.app",
                "/Applications/Filza.app",
                "/Applications/blackra1n.app",
                "/Library/MobileSubstrate/MobileSubstrate.dylib",
                "/Library/MobileSubstrate/DynamicLibraries",
                "/usr/sbin/sshd",
                "/usr/bin/sshd",
                "/usr/libexec/sftp-server",
                "/bin/bash",
                "/bin/sh",
                "/etc/apt",
                "/etc/ssh/sshd_config",
                "/private/var/lib/apt",
                "/private/var/lib/cydia",
                "/private/var/stash",
                "/private/var/mobile/Library/SBSettings",
                # Rootless & Modern Jailbreak paths
                "/var/jb/",
                "/var/jb/Applications",
                "/var/jb/usr/bin",
                "/var/jb/usr/lib",
                "/var/jb/Library/MobileSubstrate",
                "/var/jb/basebins",
                "/private/preboot/jb",
                "/jb/usr/lib",
                "/var/binpack",
                "/var/checkra1n.dmg",
                "SubstrateLoader.dylib",
                "libjailbreak.dylib",
                "ElleKit.dylib",
                "Substitute.dylib"
            ],
            "regex": [
                r"/Applications/(?:Cydia|Sileo|Zebra|Filza)\.app",
                r"/Library/MobileSubstrate",
                r"/var/jb/(?:Applications|usr|Library|basebins)",
                r"/usr/s?bin/sshd",
                r"libjailbreak\.dylib",
                r"ElleKit"
            ]
        }
    },
    {
        "id": "JB-002",
        "category": RuleCategory.JAILBREAK,
        "severity": Severity.HIGH,
        "title": "越狱 URL Scheme 协议调用探测",
        "description": "通过 -[UIApplication canOpenURL:] 检测是否能唤起 Cydia、Sileo、Zebra、Filza 等越狱商店或工具的 URL Scheme。",
        "remediation": "Hook `-[UIApplication canOpenURL:]`，当参数 URL 以 `cydia://`, `sileo://`, `zbra://`, `filza://` 开头时强制返回 NO (False)。",
        "patterns": {
            "strings": [
                "cydia://",
                "cydia://package/",
                "sileo://",
                "sileo://package/",
                "zbra://",
                "filza://",
                "undecimus://",
                "taurine://"
            ],
            "regex": [
                r"\b(?:cydia|sileo|zbra|filza|undecimus|taurine)://",
                r"canOpenURL:"
            ]
        }
    },
    {
        "id": "JB-003",
        "category": RuleCategory.JAILBREAK,
        "severity": Severity.HIGH,
        "title": "沙盒逃逸与非受信目录写入测试",
        "description": "应用尝试在沙盒外部目录（如 /private/, /var/mobile/, /root/ 等）创建或写入临时测试文件，若写入成功则判定沙盒已损坏/处于越狱环境。",
        "remediation": "Hook `writeToFile:atomically:`, `-[NSFileManager createFileAtPath:contents:attributes:]`, `open`, `creat` 等文件写入 API，拦截针对 `/private/`、`/var/` 等沙盒外目录的写入操作并模拟返回写入失败错误 (Permission Denied)。",
        "patterns": {
            "strings": [
                "/private/jailbreak.txt",
                "/private/test_jb.txt",
                "/private/test.txt",
                "/private/var/mobile/test.txt",
                "/private/tmp/test.txt",
                "writeToFile:atomically:",
                "createFileAtPath:contents:attributes:"
            ],
            "regex": [
                r"/private/(?:jailbreak|test|jb|tmp_jb)\.txt",
                r"writeToFile:\s*atomically:"
            ]
        }
    },
    {
        "id": "JB-004",
        "category": RuleCategory.JAILBREAK,
        "severity": Severity.HIGH,
        "title": "Dyld 动态库注入与镜像遍历检测",
        "description": "调用 _dyld_image_count 与 _dyld_get_image_name 遍历进程内所有加载的动态库，匹配越狱注入模块（如 Substrate, Substitute, ElleKit, Frida, CydiaSubstrate 等）。",
        "remediation": "Hook `_dyld_get_image_name` 与 `_dyld_image_count`，在遍历时隐藏或跳过越狱注入库名称，或 Hook `dlopen`/`dlsym` 阻断特定探测。",
        "patterns": {
            "imports": [
                "_dyld_get_image_name",
                "dyld_get_image_name",
                "_dyld_image_count",
                "dyld_image_count",
                "_dyld_get_image_header",
                "dyld_get_image_header"
            ],
            "symbols": [
                "_dyld_get_image_name",
                "dyld_get_image_name",
                "_dyld_image_count",
                "dyld_image_count"
            ],
            "strings": [
                "MobileSubstrate",
                "CydiaSubstrate",
                "Substitute",
                "ElleKit",
                "libhooker",
                "TweakInject",
                "PreferenceLoader",
                "SSLKillSwitch"
            ],
            "regex": [
                r"_dyld_(?:get_image_name|image_count)",
                r"(?:MobileSubstrate|CydiaSubstrate|Substitute|ElleKit|libhooker|SSLKillSwitch)"
            ]
        }
    },
    {
        "id": "JB-005",
        "category": RuleCategory.JAILBREAK,
        "severity": Severity.MEDIUM,
        "title": "外部命令执行与子进程派生 (fork/system/popen)",
        "description": "调用 system(), popen(), fork(), posix_spawn() 执行系统 Shell 命令（如 /bin/sh、/bin/ls）。在标准未越狱沙盒中由于没有 Shell 二进制或限制权限通常会失败。",
        "remediation": "Hook `system`, `popen`, `fork`, `posix_spawn`, `posix_spawnp`，当入参尝试执行 shell 命令或越狱工具时返回 -1 或模拟失败。",
        "patterns": {
            "imports": [
                "_system", "system",
                "_popen", "popen",
                "_fork", "fork",
                "_posix_spawn", "posix_spawn",
                "_posix_spawnp", "posix_spawnp"
            ],
            "symbols": ["_system", "system", "_popen", "popen", "_fork", "fork"],
            "strings": [
                "/bin/sh",
                "/bin/bash",
                "system",
                "popen",
                "posix_spawn"
            ],
            "regex": [
                r"\b(?:system|popen|posix_spawn)\s*\(",
                r"/bin/(?:sh|bash)"
            ]
        }
    },
    {
        "id": "JB-006",
        "category": RuleCategory.JAILBREAK,
        "severity": Severity.MEDIUM,
        "title": "符号链接与只读分区写权限探测",
        "description": "检查 /Applications 是否为指向 /var/stash 的软链接 (lstat/readlink)，或检查根文件系统 / 是否被重挂载为可读写 (statfs / ST_RDONLY)。",
        "remediation": "Hook `lstat`, `readlink`, `statfs` 使其对系统目录保持未越狱状态下的标准返回值与挂载标志。",
        "patterns": {
            "imports": ["_readlink", "readlink", "_lstat", "lstat", "_statfs", "statfs"],
            "strings": ["readlink", "statfs", "MNT_RDONLY", "/Applications"],
            "regex": [r"readlink\s*\(", r"statfs\s*\("]
        }
    },
    {
        "id": "JB-007",
        "category": RuleCategory.JAILBREAK,
        "severity": Severity.MEDIUM,
        "title": "第三方越狱检测库集成",
        "description": "直接集成了知名开源或商业越狱检测框架（如 IOSSecuritySuite, DTTJailbreakDetection, ANSJailbreakDetector 等）。",
        "remediation": "直接针对集成库的关键类方法进行整体 Hook（例如 `-[IOSSecuritySuite amIJailbroken]`、`+[DTTJailbreakDetection isJailbroken]` 等统一返回 False）。",
        "patterns": {
            "strings": [
                "IOSSecuritySuite",
                "amIJailbroken",
                "amIRuntimeHooked",
                "amIProxied",
                "amIDebugged",
                "amIReverseEngineered",
                "DTTJailbreakDetection",
                "isJailbroken",
                "ANSJailbreakDetector",
                "JBDetector",
                "ShieldCheck"
            ],
            "regex": [
                r"IOSSecuritySuite",
                r"amI(?:Jailbroken|RuntimeHooked|Proxied|Debugged|ReverseEngineered)",
                r"DTTJailbreakDetection",
                r"isJailbroken"
            ]
        }
    }
]
