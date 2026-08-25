# -*- coding: utf-8 -*-
"""
规则系统基础模型与数据定义
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Set


class RuleCategory(Enum):
    ANTI_DEBUG = "反调试 (Anti-Debug)"
    JAILBREAK = "越狱检测 (Jailbreak Detection)"
    SSL_PINNING = "SSL证书固定 (SSL Pinning)"
    FRIDA_HOOK = "Frida/Hook检测 (Frida & Hook)"
    SECURITY_FLAGS = "编译安全保护 (Binary Protections)"
    CONFIG_SECURITY = "应用配置安全 (App Security Config)"


class Severity(Enum):
    CRITICAL = "强防护 / 高危"
    HIGH = "高"
    MEDIUM = "中"
    LOW = "低"
    INFO = "信息"


@dataclass
class MatchLocation:
    binary_name: str          # 命中所在二进制名称（如主二进制或某个 .framework / dylib）
    binary_path: str          # 二进制相对 App 包的路径
    match_type: str           # 命中类型：'symbol', 'import', 'string', 'regex', 'framework', 'config', 'header'
    target: str               # 命中目标具体内容（符号名/字符串/特征）
    context: Optional[str] = None   # 命中上下文或说明


@dataclass
class Finding:
    rule_id: str
    category: RuleCategory
    severity: Severity
    title: str
    description: str
    remediation: str          # 逆向与防御分析建议（如如何 Hook 或绕过）
    matches: List[MatchLocation] = field(default_factory=list)
    confidence: str = "High"  # 置信度：High, Medium, Low

    def add_match(self, match: MatchLocation):
        self.matches.append(match)

    @property
    def match_count(self) -> int:
        return len(self.matches)


@dataclass
class TargetBinaryInfo:
    name: str
    rel_path: str
    abs_path: str
    is_main: bool = False
    is_framework: bool = False
    is_plugin: bool = False
    archs: List[str] = field(default_factory=list)
    is_encrypted: bool = False
    cryptid: int = 0
    has_pie: bool = False
    has_canary: bool = False
    has_arc: bool = False
    has_rpath: bool = False
    imports: Set[str] = field(default_factory=set)
    exports: Set[str] = field(default_factory=set)
    dylibs: List[str] = field(default_factory=list)
    strings: Set[str] = field(default_factory=set)
    text_content: str = ""    # 合并后的字符串全文（供正则快速检索）
