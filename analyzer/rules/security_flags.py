# -*- coding: utf-8 -*-
"""
Mach-O 编译加固与应用配置安全规则库 (Binary Protections & Config Rules)
"""

from typing import List, Dict, Any
from .base import RuleCategory, Severity


SECURITY_CONFIG_RULES: List[Dict[str, Any]] = [
    {
        "id": "SEC-001",
        "category": RuleCategory.SECURITY_FLAGS,
        "severity": Severity.MEDIUM,
        "title": "未开启 PIE (地址空间布局随机化) 保护",
        "description": "二进制文件未启用 Position Independent Executable (PIE) 编译选项，导致代码段固定在已知内存基址，大幅降低 ROP 与内存攻击门槛。",
        "remediation": "在 Xcode Build Settings 中将 `Generate Position-Dependent Code` 设为 NO，开启 `-fPIE -pie` 标志。",
        "patterns": {
            "check_type": "pie_missing"
        }
    },
    {
        "id": "SEC-002",
        "category": RuleCategory.SECURITY_FLAGS,
        "severity": Severity.MEDIUM,
        "title": "缺少 Stack Canary (栈溢出金丝雀防护)",
        "description": "二进制中未发现 `___stack_chk_guard` 或 `___stack_chk_fail` 符号，说明编译时未开启栈溢出保护，存在栈溢出覆盖返回地址风险。",
        "remediation": "在 Xcode Build Settings 中开启 `Stack Smash Protection` (`-fstack-protector-all`)。",
        "patterns": {
            "check_type": "canary_missing"
        }
    },
    {
        "id": "SEC-003",
        "category": RuleCategory.SECURITY_FLAGS,
        "severity": Severity.INFO,
        "title": "Mach-O 处于加密加锁状态 (App Store 加密/未砸壳)",
        "description": "检测到 Mach-O 头部 LC_ENCRYPTION_INFO 的 cryptid 为 1，说明二进制仍在 FairPlay DRM 加密状态下，静态反编译和部分符号分析将受到限制。",
        "remediation": "使用本项目的 dump.py 砸壳脚本先在越狱设备上完成动态脱壳后，再进行深度静态反编译与符号分析。",
        "patterns": {
            "check_type": "encrypted"
        }
    },
    {
        "id": "CFG-001",
        "category": RuleCategory.CONFIG_SECURITY,
        "severity": Severity.HIGH,
        "title": "App Transport Security (ATS) 允许全局明文 HTTP 通信",
        "description": "Info.plist 中配置了 `NSAppTransportSecurity -> NSAllowsArbitraryLoads = True`，禁用了系统级 HTTPS 强制要求，存在敏感数据明文传输及中间人截获风险。",
        "remediation": "若非必要，在 Info.plist 中移除 `NSAllowsArbitraryLoads`，仅在 `NSExceptionDomains` 中为特定可信域名配置白名单例外。",
        "patterns": {
            "check_type": "ats_arbitrary_loads"
        }
    },
    {
        "id": "CFG-002",
        "category": RuleCategory.CONFIG_SECURITY,
        "severity": Severity.MEDIUM,
        "title": "ATS 允许加载不安全的 HTTP 媒体/网页资源",
        "description": "Info.plist 中配置了 `NSAllowsArbitraryLoadsInWebContent` 或 `NSAllowsArbitraryLoadsForMedia`，允许在 WKWebView 或多媒体播放中加载非 HTTPS 资源。",
        "remediation": "确保 Web 资源与多媒体服务端均迁移至全站 HTTPS，降低被流量劫持篡改展示内容的风险。",
        "patterns": {
            "check_type": "ats_insecure_suboptions"
        }
    }
]
