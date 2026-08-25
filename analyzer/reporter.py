# -*- coding: utf-8 -*-
"""
多格式安全分析报告生成器 (Multi-Format Reporter)
支持：
1. 终端彩色高亮表格 (Console/Terminal)
2. 结构化 JSON 输出 (JSON)
3. Markdown 审计报告 (Markdown)
4. 现代化独立 HTML 交互式报告 (HTML)
"""

import json
import os
from typing import List, Dict, Any
from .engine import AnalysisResult, AnalysisSummary
from .rules.base import Severity, RuleCategory


# 控制台 ANSI 颜色
class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


class ConsoleReporter:
    """终端彩色格式化报告"""

    @classmethod
    def print_report(cls, result: AnalysisResult, verbose: bool = False):
        pkg = result.package_info
        summary = result.summary

        print("\n" + "=" * 80)
        print(f"{Color.BOLD}{Color.CYAN}       iOS IPA 静态安全防护与检测点分析报告 (IPA Security Analyzer){Color.RESET}")
        print("=" * 80)

        # 1. 基础信息卡片
        print(f"\n{Color.BOLD}[+] 目标应用基本信息:{Color.RESET}")
        print(f"  • 应用名称 (Name)      : {Color.BOLD}{pkg.display_name or pkg.bundle_name}{Color.RESET}")
        print(f"  • 包标识符 (Bundle ID)  : {Color.GREEN}{pkg.bundle_id}{Color.RESET}")
        print(f"  • 应用版本 (Version)    : {pkg.bundle_version}")
        print(f"  • 最低系统 (Min iOS)    : {pkg.min_os_version or 'N/A'}")
        print(f"  • 主可执行文件         : {pkg.executable_name}")
        
        main_archs = ", ".join(pkg.main_binary.archs) if pkg.main_binary else "Unknown"
        print(f"  • 支持架构 (Archs)      : {main_archs}")
        
        # 砸壳状态
        if summary.is_encrypted:
            enc_status = f"{Color.BG_RED}{Color.WHITE} 未砸壳 (FairPlay 加密) {Color.RESET} {Color.YELLOW}(建议使用 dump.py 先进行脱壳){Color.RESET}"
        else:
            enc_status = f"{Color.BG_GREEN}{Color.WHITE} 已砸壳 / 未加密 (Decrypted) {Color.RESET}"
        print(f"  • 砸壳状态 (Encryption) : {enc_status}")

        print(f"  • 扫描二进制总数       : {result.binaries_scanned_count} (主二进制 + {len(pkg.frameworks)} 个动态库 + {len(pkg.plugins)} 个扩展)")
        if pkg.certificates:
            print(f"  • 内置证书资产         : {len(pkg.certificates)} 个证书文件")

        # 2. 四大防护核心指标仪表盘
        print(f"\n{Color.BOLD}[+] 核心防护机制检测态势:{Color.RESET}")
        
        def status_tag(has: bool, name: str) -> str:
            if has:
                return f"[{Color.RED}{Color.BOLD}✓ 已发现{Color.RESET}] {name}"
            return f"[{Color.GREEN}✗ 未检出{Color.RESET}] {name}"

        print(f"  {status_tag(summary.has_anti_debug, '反调试保护 (Anti-Debug)')}   "
              f"{status_tag(summary.has_jailbreak_detection, '越狱检测 (Jailbreak)')}")
        print(f"  {status_tag(summary.has_ssl_pinning, 'SSL证书固定 (Pinning)')}    "
              f"{status_tag(summary.has_frida_detection, 'Frida/Hook 检测')}")

        # 防护强度评分
        score_color = Color.RED if summary.defense_score >= 60 else (Color.YELLOW if summary.defense_score >= 30 else Color.GREEN)
        print(f"\n  • 综合安全防护强度评分 : {score_color}{Color.BOLD}{summary.defense_score} / 100{Color.RESET} "
              f"({summary.critical_count} 项强防护, {summary.high_count} 项高危/高强度, {summary.medium_count} 项中等)")

        # 3. 详细检测结果列表
        print("\n" + "-" * 80)
        print(f"{Color.BOLD}[+] 检测点与防护规则命中详情 ({len(result.findings)} 项命中):{Color.RESET}")
        print("-" * 80)

        if not result.findings:
            print(f"{Color.GREEN}  未检测到已知的反调试、越狱、SSL固定或Frida检测规则特征。{Color.RESET}")
            return

        for idx, finding in enumerate(result.findings, 1):
            sev_color = Color.RED if finding.severity in (Severity.CRITICAL, Severity.HIGH) else (Color.YELLOW if finding.severity == Severity.MEDIUM else Color.CYAN)
            print(f"\n{Color.BOLD}#{idx:02d} [{finding.rule_id}] {finding.title}{Color.RESET}")
            print(f"  • 类别 (Category) : {finding.category.value}")
            print(f"  • 级别 (Severity) : {sev_color}{finding.severity.value}{Color.RESET}")
            print(f"  • 描述说明        : {finding.description}")
            print(f"  • 命中位置数量    : {Color.BOLD}{finding.match_count}{Color.RESET} 处")

            # 打印命中位置
            shown_matches = finding.matches if verbose else finding.matches[:5]
            for m in shown_matches:
                print(f"    - [{m.match_type.upper()}] {Color.CYAN}{m.binary_name}{Color.RESET} -> {Color.YELLOW}{m.target}{Color.RESET} ({m.context})")
            if not verbose and finding.match_count > 5:
                print(f"    - {Color.DIM}... 还有 {finding.match_count - 5} 处命中，使用 --verbose 查看全部{Color.RESET}")

            print(f"  • {Color.MAGENTA}逆向/防护应对建议{Color.RESET}: {finding.remediation}")

        print("\n" + "=" * 80 + "\n")


class JSONReporter:
    """JSON 格式化导出器"""

    @classmethod
    def generate(cls, result: AnalysisResult) -> str:
        pkg = result.package_info
        summary = result.summary

        data = {
            "app_info": {
                "bundle_id": pkg.bundle_id,
                "bundle_name": pkg.bundle_name,
                "display_name": pkg.display_name,
                "version": pkg.bundle_version,
                "min_os_version": pkg.min_os_version,
                "executable_name": pkg.executable_name,
                "is_encrypted": summary.is_encrypted,
                "url_schemes": pkg.url_schemes,
                "binaries_scanned_count": result.binaries_scanned_count,
            },
            "summary": {
                "defense_score": summary.defense_score,
                "total_findings": summary.total_findings,
                "critical_count": summary.critical_count,
                "high_count": summary.high_count,
                "medium_count": summary.medium_count,
                "low_count": summary.low_count,
                "info_count": summary.info_count,
                "has_anti_debug": summary.has_anti_debug,
                "has_jailbreak_detection": summary.has_jailbreak_detection,
                "has_ssl_pinning": summary.has_ssl_pinning,
                "has_frida_detection": summary.has_frida_detection,
            },
            "findings": []
        }

        for f in result.findings:
            f_dict = {
                "rule_id": f.rule_id,
                "category": f.category.name,
                "category_label": f.category.value,
                "severity": f.severity.name,
                "severity_label": f.severity.value,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "match_count": f.match_count,
                "matches": [
                    {
                        "binary_name": m.binary_name,
                        "binary_path": m.binary_path,
                        "match_type": m.match_type,
                        "target": m.target,
                        "context": m.context
                    }
                    for m in f.matches
                ]
            }
            data["findings"].append(f_dict)

        return json.dumps(data, ensure_ascii=False, indent=2)


class MarkdownReporter:
    """Markdown 格式分析报告"""

    @classmethod
    def generate(cls, result: AnalysisResult) -> str:
        pkg = result.package_info
        summary = result.summary

        lines = [
            f"# iOS IPA 静态安全分析报告 - {pkg.display_name or pkg.bundle_name}",
            "",
            "## 1. 目标应用基本信息",
            "",
            f"| 属性 | 值 |",
            f"| :--- | :--- |",
            f"| **应用标识 (Bundle ID)** | `{pkg.bundle_id}` |",
            f"| **应用名称 (Name)** | {pkg.display_name or pkg.bundle_name} |",
            f"| **版本号 (Version)** | {pkg.bundle_version} |",
            f"| **主程序文件** | `{pkg.executable_name}` |",
            f"| **砸壳加密状态** | {'🔴 未砸壳 (FairPlay 加密)' if summary.is_encrypted else '🟢 已脱壳 / 未加密'} |",
            f"| **扫描二进制组件数** | {result.binaries_scanned_count} 个 (主可执行文件 + Frameworks 动态库 + 插件) |",
            "",
            "## 2. 核心防护态势汇总",
            "",
            f"- **反调试保护 (Anti-Debug)**: {'🔴 已检测到防御点' if summary.has_anti_debug else '🟢 未检出'}",
            f"- **越狱环境检测 (Jailbreak)**: {'🔴 已检测到防御点' if summary.has_jailbreak_detection else '🟢 未检出'}",
            f"- **HTTPS 证书固定 (SSL Pinning)**: {'🔴 已检测到防御点' if summary.has_ssl_pinning else '🟢 未检出'}",
            f"- **Frida / Hook 检测**: {'🔴 已检测到防御点' if summary.has_frida_detection else '🟢 未检出'}",
            f"- **综合加固防护指数**: **{summary.defense_score} / 100**",
            "",
            "## 3. 防护检测点明细",
            ""
        ]

        for idx, f in enumerate(result.findings, 1):
            lines.append(f"### {idx}. [{f.rule_id}] {f.title}")
            lines.append(f"- **分类**: {f.category.value}")
            lines.append(f"- **严重级别**: `{f.severity.value}`")
            lines.append(f"- **机制描述**: {f.description}")
            lines.append(f"- **逆向/防御应对建议**: {f.remediation}")
            lines.append("")
            lines.append("#### 命中位置与上下文")
            lines.append("| 目标组件 | 匹配类型 | 命中特征 | 详细说明 |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for m in f.matches:
                lines.append(f"| `{m.binary_name}` | `{m.match_type}` | `{m.target}` | {m.context or '-'} |")
            lines.append("")

        return "\n".join(lines)


class HTMLReporter:
    """现代化独立交互式 HTML 报告生成器"""

    @classmethod
    def generate(cls, result: AnalysisResult) -> str:
        pkg = result.package_info
        summary = result.summary
        json_data = JSONReporter.generate(result)

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPA 安全防护与检测点分析报告 - {pkg.display_name or pkg.bundle_name}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-dim: #94a3b8;
            --primary: #38bdf8;
            --accent: #818cf8;
            --danger: #f87171;
            --warning: #fbbf24;
            --success: #34d399;
            --info: #60a5fa;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            padding: 30px 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }}
        h1 {{ font-size: 24px; color: var(--primary); }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge-danger {{ background: rgba(248, 113, 113, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
        .badge-warning {{ background: rgba(251, 191, 36, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
        .badge-success {{ background: rgba(52, 211, 153, 0.2); color: var(--success); border: 1px solid var(--success); }}
        .badge-info {{ background: rgba(96, 165, 250, 0.2); color: var(--info); border: 1px solid var(--info); }}
        
        .grid-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3);
        }}
        .card h3 {{ font-size: 14px; color: var(--text-dim); margin-bottom: 8px; text-transform: uppercase; }}
        .card .stat-val {{ font-size: 28px; font-weight: bold; }}
        
        .section-title {{ font-size: 18px; margin: 30px 0 15px 0; color: var(--accent); }}
        
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 15px;
            overflow: hidden;
            transition: all 0.2s;
        }}
        .finding-header {{
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background: rgba(255,255,255,0.02);
        }}
        .finding-header:hover {{ background: rgba(255,255,255,0.05); }}
        .finding-body {{ padding: 20px; border-top: 1px solid var(--border); }}
        .remediation-box {{
            background: rgba(129, 140, 248, 0.1);
            border-left: 4px solid var(--accent);
            padding: 12px 16px;
            margin-top: 15px;
            border-radius: 0 6px 6px 0;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 13px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
        }}
        th {{ background: rgba(0,0,0,0.2); color: var(--text-dim); }}
        code {{
            background: #090d16;
            color: #38bdf8;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>📱 iOS IPA 静态安全防护检测报告</h1>
                <p style="color: var(--text-dim); margin-top: 4px;">目标包: <code>{os.path.basename(pkg.ipa_path)}</code></p>
            </div>
            <div>
                <span class="badge {'badge-danger' if summary.is_encrypted else 'badge-success'}">
                    {'🔴 FairPlay 加密未砸壳' if summary.is_encrypted else '🟢 已砸壳脱壳'}
                </span>
            </div>
        </header>

        <div class="grid-cards">
            <div class="card">
                <h3>应用标识 (Bundle ID)</h3>
                <div style="font-size: 16px; font-weight: bold; color: var(--primary);">{pkg.bundle_id or 'Unknown'}</div>
                <p style="font-size: 12px; color: var(--text-dim); margin-top: 5px;">版本: {pkg.bundle_version} | Min iOS: {pkg.min_os_version}</p>
            </div>
            <div class="card">
                <h3>防护综合强度</h3>
                <div class="stat-val" style="color: {'var(--danger)' if summary.defense_score >= 60 else ('var(--warning)' if summary.defense_score >= 30 else 'var(--success)')};">
                    {summary.defense_score} <span style="font-size: 14px; color: var(--text-dim);">/ 100</span>
                </div>
                <p style="font-size: 12px; color: var(--text-dim); margin-top: 5px;">发现 {summary.total_findings} 项防护与安全特征</p>
            </div>
            <div class="card">
                <h3>扫描二进制组件</h3>
                <div class="stat-val" style="color: var(--info);">{result.binaries_scanned_count} <span style="font-size: 14px; color: var(--text-dim);">个 Mach-O</span></div>
                <p style="font-size: 12px; color: var(--text-dim); margin-top: 5px;">主程序 + {len(pkg.frameworks)} 个 Frameworks + {len(pkg.plugins)} 个插件</p>
            </div>
            <div class="card">
                <h3>核心防御态势</h3>
                <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px;">
                    <span class="badge {'badge-danger' if summary.has_anti_debug else 'badge-success'}">反调试: {'有' if summary.has_anti_debug else '无'}</span>
                    <span class="badge {'badge-danger' if summary.has_jailbreak_detection else 'badge-success'}">越狱检测: {'有' if summary.has_jailbreak_detection else '无'}</span>
                    <span class="badge {'badge-danger' if summary.has_ssl_pinning else 'badge-success'}">SSL Pinning: {'有' if summary.has_ssl_pinning else '无'}</span>
                    <span class="badge {'badge-danger' if summary.has_frida_detection else 'badge-success'}">Frida检测: {'有' if summary.has_frida_detection else '无'}</span>
                </div>
            </div>
        </div>

        <h2 class="section-title">🔍 检测点与防护规则命中详情 ({len(result.findings)})</h2>
"""

        for idx, f in enumerate(result.findings, 1):
            sev_class = "badge-danger" if f.severity in (Severity.CRITICAL, Severity.HIGH) else ("badge-warning" if f.severity == Severity.MEDIUM else "badge-info")
            html += f"""
        <div class="finding-card">
            <div class="finding-header">
                <div>
                    <span style="font-weight: bold; font-size: 16px;">#{idx:02d} [{f.rule_id}] {f.title}</span>
                    <span style="color: var(--text-dim); font-size: 13px; margin-left: 10px;">({f.category.value})</span>
                </div>
                <div>
                    <span class="badge {sev_class}">{f.severity.value}</span>
                </div>
            </div>
            <div class="finding-body">
                <p style="font-size: 14px; color: var(--text);">{f.description}</p>
                
                <table>
                    <thead>
                        <tr>
                            <th>组件/文件</th>
                            <th>类型</th>
                            <th>命中内容/符号</th>
                            <th>详细说明</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for m in f.matches:
                html += f"""
                        <tr>
                            <td><code>{m.binary_name}</code></td>
                            <td><span class="badge badge-info">{m.match_type}</span></td>
                            <td><code>{m.target}</code></td>
                            <td>{m.context or '-'}</td>
                        </tr>
"""
            html += f"""
                    </tbody>
                </table>

                <div class="remediation-box">
                    <strong>💡 逆向与防御应对建议:</strong> {f.remediation}
                </div>
            </div>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""
        return html
