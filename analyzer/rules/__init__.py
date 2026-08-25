# -*- coding: utf-8 -*-
"""
规则库模块统一导出
"""

from typing import List, Dict, Any
from .base import RuleCategory, Severity, Finding, MatchLocation, TargetBinaryInfo
from .anti_debug import ANTI_DEBUG_RULES
from .jailbreak import JAILBREAK_RULES
from .ssl_pinning import SSL_PINNING_RULES
from .frida_hook import FRIDA_HOOK_RULES
from .security_flags import SECURITY_CONFIG_RULES


def get_all_rules() -> List[Dict[str, Any]]:
    """获取所有静态分析检测规则"""
    return (
        ANTI_DEBUG_RULES
        + JAILBREAK_RULES
        + SSL_PINNING_RULES
        + FRIDA_HOOK_RULES
        + SECURITY_CONFIG_RULES
    )


__all__ = [
    "RuleCategory",
    "Severity",
    "Finding",
    "MatchLocation",
    "TargetBinaryInfo",
    "ANTI_DEBUG_RULES",
    "JAILBREAK_RULES",
    "SSL_PINNING_RULES",
    "FRIDA_HOOK_RULES",
    "SECURITY_CONFIG_RULES",
    "get_all_rules"
]
