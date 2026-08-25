#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iOS IPA 静态安全分析工具 (IPA Security Analyzer)
用于自动化分析 iOS IPA / App 包中的反调试、越狱检测、SSL Pinning 证书固定、Frida/Hook 检测等安全防护特征与风险点。

使用示例:
  python3 analyze.py -f target.ipa
  python3 analyze.py -f target.ipa -o report.html
  python3 analyze.py -f target.ipa -o report.json --json
  python3 analyze.py -f target.ipa --verbose
"""

import argparse
import os
import sys
import time

# 将当前目录加入模块搜索路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import (
    IPAParser,
    AnalysisEngine,
    ConsoleReporter,
    JSONReporter,
    MarkdownReporter,
    HTMLReporter,
    TweakGenerator
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="iOS IPA 静态安全防护与检测点分析工具 (Anti-Debug, Jailbreak, SSL Pinning, Frida Detection)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-f", "--file",
        dest="target_file",
        required=True,
        help="目标 .ipa 文件路径或已解压的 .app 目录路径"
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        default=None,
        help="导出分析报告的文件路径 (例如: report.html, report.json, report.md)"
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=["console", "json", "markdown", "html"],
        default=None,
        help="指定输出报告格式 (默认根据 output 文件后缀自动推断，未指定则仅控制台打印)"
    )
    parser.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="显示全部命中详细列表与上下文信息"
    )
    parser.add_argument(
        "--json",
        dest="json_only",
        action="store_true",
        help="直接向标准输出打印 JSON 格式结果"
    )
    parser.add_argument(
        "--gen-tweak",
        dest="gen_tweak_dir",
        nargs="?",
        const="DEFAULT",
        default=None,
        help="根据扫描结果自动生成 Theos Tweak 插件工程与 Frida Bypass 脚本 (可指定输出目录)"
    )
    parser.add_argument(
        "--keep-temp",
        dest="keep_temp",
        action="store_true",
        help="分析完成后保留临时解压目录"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    target_path = os.path.abspath(args.target_file)
    if not os.path.exists(target_path):
        print(f"\033[91m[-] 错误: 目标文件或目录不存在: {target_path}\033[0m", file=sys.stderr)
        sys.exit(1)

    if not args.json_only:
        print(f"\033[94m[*] 正在加载并解析 IPA 目标: {os.path.basename(target_path)} ...\033[0m")

    start_time = time.time()
    ipa_parser = IPAParser(target_path)

    try:
        # 1. 解包并发现资产
        pkg_info = ipa_parser.parse()
        if not args.json_only:
            print(f"\033[94m[*] 成功定位应用: {pkg_info.bundle_id or pkg_info.bundle_name}, 发现 {len(pkg_info.frameworks)} 个 Framework 动态库\033[0m")
            print(f"\033[94m[*] 正在执行多规则静态特征匹配与反调试/越狱/SSL固定/Frida检测点扫描 ...\033[0m")

        # 2. 执行静态分析
        engine = AnalysisEngine(pkg_info)
        result = engine.run()

        elapsed = time.time() - start_time

        # 3. 输出报告
        if args.json_only:
            print(JSONReporter.generate(result))
        else:
            ConsoleReporter.print_report(result, verbose=args.verbose)
            print(f"\033[90m[*] 扫描分析耗时: {elapsed:.2f} 秒\033[0m")

        # 4. 导出文件报告
        if args.output_file:
            out_p = os.path.abspath(args.output_file)
            fmt = args.output_format

            if not fmt:
                ext = os.path.splitext(out_p)[1].lower()
                if ext in (".html", ".htm"):
                    fmt = "html"
                elif ext in (".json",):
                    fmt = "json"
                elif ext in (".md", ".markdown"):
                    fmt = "markdown"
                else:
                    fmt = "html"

            content = ""
            if fmt == "html":
                content = HTMLReporter.generate(result)
            elif fmt == "json":
                content = JSONReporter.generate(result)
            elif fmt == "markdown":
                content = MarkdownReporter.generate(result)

            with open(out_p, "w", encoding="utf-8") as f:
                f.write(content)

            if not args.json_only:
                print(f"\033[92m[+] 分析报告已成功保存至: {out_p} ({fmt.upper()})\033[0m")

        # 5. 自动生成 Tweak 插件工程
        if args.gen_tweak_dir:
            app_name = pkg_info.executable_name or pkg_info.bundle_name or "App"
            if args.gen_tweak_dir == "DEFAULT":
                tweak_dir = os.path.abspath(f"./{app_name}Bypass")
            else:
                tweak_dir = os.path.abspath(args.gen_tweak_dir)

            generator = TweakGenerator(result)
            gen_files = generator.generate_project(tweak_dir)
            if not args.json_only:
                print(f"\033[92m[+] 已成功在 '{tweak_dir}' 生成定制化 Theos Tweak 插件工程与 Frida Bypass 脚本!\033[0m")

    except Exception as e:
        print(f"\033[91m[-] 分析过程发生异常: {str(e)}\033[0m", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if not args.keep_temp:
            ipa_parser.cleanup()


if __name__ == "__main__":
    main()
