# -*- coding: utf-8 -*-
"""
静态安全分析调度引擎 (Analysis Engine)
执行多规则并行/顺序匹配、聚合检测结果并计算防护强度与风险等级
"""

import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from .rules import (
    RuleCategory,
    Severity,
    Finding,
    MatchLocation,
    TargetBinaryInfo,
    get_all_rules
)
from .ipa_parser import AppPackageInfo


@dataclass
class AnalysisSummary:
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    defense_score: int = 0       # 应用防护与加固强度评分 (0 ~ 100)
    has_anti_debug: bool = False
    has_jailbreak_detection: bool = False
    has_ssl_pinning: bool = False
    has_frida_detection: bool = False
    is_encrypted: bool = False


@dataclass
class AnalysisResult:
    package_info: AppPackageInfo
    findings: List[Finding] = field(default_factory=list)
    summary: AnalysisSummary = field(default_factory=AnalysisSummary)
    binaries_scanned_count: int = 0


class AnalysisEngine:
    """静态分析执行与汇总引擎"""

    def __init__(self, package_info: AppPackageInfo):
        self.pkg = package_info
        self.rules = get_all_rules()

    def run(self) -> AnalysisResult:
        """执行全量扫描"""
        result = AnalysisResult(package_info=self.pkg)

        # 收集所有待扫二进制
        all_binaries: List[TargetBinaryInfo] = []
        if self.pkg.main_binary:
            all_binaries.append(self.pkg.main_binary)
        all_binaries.extend(self.pkg.frameworks)
        all_binaries.extend(self.pkg.plugins)

        result.binaries_scanned_count = len(all_binaries)

        # 逐条规则执行扫描
        for rule in self.rules:
            finding = self._evaluate_rule(rule, all_binaries)
            if finding and finding.match_count > 0:
                result.findings.append(finding)

        # 计算汇总与评分
        self._calculate_summary(result)

        return result

    def _evaluate_rule(self, rule: Dict[str, Any], binaries: List[TargetBinaryInfo]) -> Optional[Finding]:
        """针对单个规则进行全包与二进制匹配"""
        rule_id = rule["id"]
        category = rule["category"]
        severity = rule["severity"]
        title = rule["title"]
        description = rule["description"]
        remediation = rule["remediation"]
        patterns = rule.get("patterns", {})

        finding = Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation
        )

        # 特殊检查类型 1: 二进制加固属性 (PIE, Canary, Encrypted)
        check_type = patterns.get("check_type")
        if check_type:
            self._handle_special_check(check_type, finding, binaries)
            return finding if finding.match_count > 0 else None

        # 特殊检查类型 2: 证书文件资产
        if "file_exts" in patterns:
            if self.pkg.certificates:
                for cert in self.pkg.certificates:
                    finding.add_match(
                        MatchLocation(
                            binary_name="App Bundle 资源",
                            binary_path=cert.rel_path,
                            match_type="asset",
                            target=cert.file_name,
                            context=f"发现内嵌证书文件 ({cert.size_bytes} 字节)"
                        )
                    )
            return finding if finding.match_count > 0 else None

        # 通用 Mach-O 匹配（Imports, Symbols, Strings, Regex）
        for b in binaries:
            # 1. Imports 匹配
            for imp in patterns.get("imports", []):
                if imp in b.imports:
                    finding.add_match(
                        MatchLocation(
                            binary_name=b.name,
                            binary_path=b.rel_path,
                            match_type="import",
                            target=imp,
                            context="动态导入 C 符号/系统 API"
                        )
                    )

            # 2. Symbols 匹配
            for sym in patterns.get("symbols", []):
                if sym in b.exports or sym in b.imports:
                    finding.add_match(
                        MatchLocation(
                            binary_name=b.name,
                            binary_path=b.rel_path,
                            match_type="symbol",
                            target=sym,
                            context="符号表中存在特征符号"
                        )
                    )

            # 3. Strings 精确/子串匹配
            for st in patterns.get("strings", []):
                if st in b.strings:
                    finding.add_match(
                        MatchLocation(
                            binary_name=b.name,
                            binary_path=b.rel_path,
                            match_type="string",
                            target=st,
                            context="二进制文本/常量段匹配到特征字符串"
                        )
                    )

            # 4. Regex 正则匹配
            for reg_pat in patterns.get("regex", []):
                try:
                    compiled = re.compile(reg_pat, re.IGNORECASE)
                    matches = compiled.findall(b.text_content)
                    if matches:
                        sample_m = matches[0] if isinstance(matches[0], str) else matches[0][0]
                        finding.add_match(
                            MatchLocation(
                                binary_name=b.name,
                                binary_path=b.rel_path,
                                match_type="regex",
                                target=sample_m,
                                context=f"正则模式 /{reg_pat}/ 匹配成功 ({len(matches)} 次)"
                            )
                        )
                except Exception:
                    pass

        # 去除同一二进制内的完全重复 Match
        unique_matches: List[MatchLocation] = []
        seen = set()
        for m in finding.matches:
            key = (m.binary_path, m.match_type, m.target)
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)
        finding.matches = unique_matches

        return finding if finding.match_count > 0 else None

    def _handle_special_check(self, check_type: str, finding: Finding, binaries: List[TargetBinaryInfo]):
        """处理加固标志与 Plist 特殊检测"""
        if check_type == "pie_missing":
            for b in binaries:
                if not b.has_pie:
                    finding.add_match(
                        MatchLocation(
                            binary_name=b.name,
                            binary_path=b.rel_path,
                            match_type="header",
                            target="MH_PIE missing",
                            context="Mach-O 头部未设置 MH_PIE 标志"
                        )
                    )
        elif check_type == "canary_missing":
            for b in binaries:
                if b.is_main and not b.has_canary:
                    finding.add_match(
                        MatchLocation(
                            binary_name=b.name,
                            binary_path=b.rel_path,
                            match_type="symbol",
                            target="stack_chk missing",
                            context="主二进制未检测到 Stack Canary 保护符号"
                        )
                    )
        elif check_type == "encrypted":
            for b in binaries:
                if b.is_encrypted:
                    finding.add_match(
                        MatchLocation(
                            binary_name=b.name,
                            binary_path=b.rel_path,
                            match_type="header",
                            target=f"cryptid={b.cryptid}",
                            context="LC_ENCRYPTION_INFO 处于加密状态 (FairPlay DRM)"
                        )
                    )
        elif check_type == "ats_arbitrary_loads":
            ats = self.pkg.ats_settings
            if ats.get("NSAllowsArbitraryLoads") is True:
                finding.add_match(
                    MatchLocation(
                        binary_name="Info.plist",
                        binary_path="Info.plist",
                        match_type="config",
                        target="NSAllowsArbitraryLoads = True",
                        context="全局禁用 ATS，允许所有明文 HTTP 网络请求"
                    )
                )
        elif check_type == "ats_insecure_suboptions":
            ats = self.pkg.ats_settings
            if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
                finding.add_match(
                    MatchLocation(
                        binary_name="Info.plist",
                        binary_path="Info.plist",
                        match_type="config",
                        target="NSAllowsArbitraryLoadsInWebContent = True",
                        context="允许 WKWebView 加载任意 HTTP 网页"
                    )
                )
            if ats.get("NSAllowsArbitraryLoadsForMedia") is True:
                finding.add_match(
                    MatchLocation(
                        binary_name="Info.plist",
                        binary_path="Info.plist",
                        match_type="config",
                        target="NSAllowsArbitraryLoadsForMedia = True",
                        context="允许音视频多媒体加载任意 HTTP 流"
                    )
                )

    def _calculate_summary(self, result: AnalysisResult):
        """汇总数量与计算防御强度评分"""
        summary = result.summary
        summary.total_findings = len(result.findings)

        defense_score = 0

        for f in result.findings:
            if f.severity == Severity.CRITICAL:
                summary.critical_count += 1
                defense_score += 25
            elif f.severity == Severity.HIGH:
                summary.high_count += 1
                defense_score += 15
            elif f.severity == Severity.MEDIUM:
                summary.medium_count += 1
                defense_score += 8
            elif f.severity == Severity.LOW:
                summary.low_count += 1
                defense_score += 3
            elif f.severity == Severity.INFO:
                summary.info_count += 1

            if f.category == RuleCategory.ANTI_DEBUG:
                summary.has_anti_debug = True
            elif f.category == RuleCategory.JAILBREAK:
                summary.has_jailbreak_detection = True
            elif f.category == RuleCategory.SSL_PINNING:
                summary.has_ssl_pinning = True
            elif f.category == RuleCategory.FRIDA_HOOK:
                summary.has_frida_detection = True

        if self.pkg.main_binary and self.pkg.main_binary.is_encrypted:
            summary.is_encrypted = True

        # 防护评分最高 100 分
        summary.defense_score = min(100, defense_score)
