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
        required=False,
        default=None,
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
        "--dump-objc",
        dest="dump_objc_pattern",
        nargs="?",
        const="ALL",
        default=None,
        help="导出或搜索静态解析出的 Objective-C 类定义、分类与方法 (支持模糊匹配，如: --dump-objc Message)"
    )
    parser.add_argument(
        "--xrefs",
        dest="xrefs_pattern",
        nargs="?",
        const="ALL",
        default=None,
        help="查找 ARM64 交叉引用：显示哪些函数引用了特定字符串/符号 (支持模糊关键词，如: --xrefs ptrace)"
    )
    parser.add_argument(
        "--demangle",
        dest="demangle_symbol",
        nargs="?",
        const="",
        default=None,
        help="还原指定的 Swift 混淆符号 (如: --demangle _TtC10Calculator16CalculatorLayout)"
    )
    parser.add_argument(
        "--disasm",
        dest="disasm_target",
        default=None,
        help="提取指定函数/偏移或符号特征的 ARM64 汇编指令片段 (如: --disasm 0x1E9B34 或 --disasm SwitchMode)"
    )
    parser.add_argument(
        "--disasm-count",
        dest="disasm_count",
        type=int,
        default=40,
        help="指定反汇编的最大指令条数 (默认: 40 条，遇到 ret 自动停止)"
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

    # 独立 Swift 符号还原工具模式
    if args.demangle_symbol is not None:
        from analyzer.demangler import SwiftDemangler
        sym = args.demangle_symbol.strip()
        if not sym:
            print("[\033[31m!\033[0m] 请输入要还原的 Swift 符号，例如: python3 analyze.py --demangle _TtC10Calculator16CalculatorLayout")
            sys.exit(1)
        dem = SwiftDemangler.demangle(sym)
        print(f"\n\033[1;32m[+] Swift 符号还原 (Demangled):\033[0m")
        print(f"  原始混淆名: \033[90m{sym}\033[0m")
        print(f"  还原可读名: \033[1;36m{dem}\033[0m\n")
        sys.exit(0)

    if not args.target_file:
        print("[\033[31m!\033[0m] 错误: 缺少必填目标参数 -f / --file，请输入目标 .ipa 或 .app 路径")
        sys.exit(1)

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

        # 3.5. 导出或检索 Objective-C 类与分类定义
        if args.dump_objc_pattern:
            handle_dump_objc(pkg_info, args.dump_objc_pattern)

        # 3.6. 交叉引用查找
        if args.xrefs_pattern:
            handle_xrefs(pkg_info, args.xrefs_pattern)

        # 3.7. 精准反汇编与代码片段查看
        if args.disasm_target:
            handle_disasm(pkg_info, args.disasm_target, args.disasm_count)

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


def handle_dump_objc(pkg_info, pattern: str):
    """导出并格式化打印匹配的 Objective-C 类与分类元数据"""
    targets = ([pkg_info.main_binary] if pkg_info.main_binary else []) + pkg_info.frameworks
    matched_classes = []
    matched_categories = []

    is_all = pattern.upper() == "ALL"
    pat_lower = pattern.lower()

    for bin_info in targets:
        if not bin_info:
            continue
        for cname, cinfo in bin_info.objc_classes.items():
            dem = cinfo.demangled_name or ""
            if (is_all or
                pat_lower in cname.lower() or
                pat_lower in dem.lower() or
                any(pat_lower in m.name.lower() for m in cinfo.instance_methods + cinfo.class_methods)):
                matched_classes.append((bin_info.name, cinfo))
        for cat in bin_info.objc_categories:
            dem_cat = cat.demangled_class_name or ""
            if (is_all or
                pat_lower in cat.name.lower() or
                pat_lower in cat.class_name.lower() or
                pat_lower in dem_cat.lower()):
                matched_categories.append((bin_info.name, cat))

    print("\n" + "=" * 80)
    print(f"\033[1;36m[+] Objective-C 静态类与方法检索结果 (Filter: '{pattern}'): 命中 {len(matched_classes)} 个类, {len(matched_categories)} 个分类\033[0m")
    print("=" * 80)

    for bin_name, cinfo in matched_classes[:50]:
        swift_tag = f" \033[1;36m[Swift: {cinfo.demangled_name}]\033[0m" if cinfo.demangled_name else ""
        print(f"\n\033[1;33m@interface {cinfo.name}{swift_tag} : {cinfo.super_class or 'NSObject'}\033[0m \033[90m[{bin_name}]\033[0m")
        for p in cinfo.properties:
            print(f"  @property {p};")
        for m in cinfo.class_methods:
            print(f"  + {m.name};")
        for m in cinfo.instance_methods:
            print(f"  - {m.name};")
        print("\033[1;33m@end\033[0m")

    if len(matched_classes) > 50:
        print(f"\n\033[90m... 还有 {len(matched_classes) - 50} 个匹配类，请使用更精确的搜索词过滤。\033[0m")

    for bin_name, cat in matched_categories[:20]:
        swift_cat_tag = f" \033[1;36m[Swift: {cat.demangled_class_name}]\033[0m" if cat.demangled_class_name else ""
        print(f"\n\033[1;35m@interface {cat.class_name or 'Unknown'}{swift_cat_tag} ({cat.name})\033[0m \033[90m[{bin_name}]\033[0m")
        for m in cat.instance_methods:
            print(f"  - {m.name};")
        for m in cat.class_methods:
            print(f"  + {m.name};")
        print("\033[1;35m@end\033[0m")



def handle_xrefs(pkg_info, pattern: str):
    """查找并打印 ARM64 交叉引用：哪些函数体引用了匹配 pattern 的字符串或符号"""
    from analyzer.xref_scanner import XrefScanner, XrefReport

    targets = ([pkg_info.main_binary] if pkg_info.main_binary else []) + pkg_info.frameworks

    print("\n" + "=" * 80)
    is_all = pattern.upper() == "ALL"
    label = "全量" if is_all else f"'{pattern}'"
    print(f"\033[1;34m[+] ARM64 交叉引用分析 (Xrefs) — 关键词: {label}\033[0m")
    print("=" * 80)

    total_hits = 0
    for bin_info in targets:
        if not bin_info:
            continue

        # 优先使用已计算好的 xrefs 报表，若没有则现场扫描
        report: XrefReport = bin_info.xrefs
        if report is None:
            print(f"\033[90m  [{bin_info.name}] 正在扫描 ARM64 指令流 ...\033[0m")
            scanner = XrefScanner(bin_info.abs_path)
            report = scanner.scan()

        # 按关键词过滤
        if is_all:
            all_results = []
            for results in report.by_target.values():
                all_results.extend(results)
        else:
            all_results = report.query(pattern)

        if not all_results:
            continue

        print(f"\n\033[93m  [{bin_info.name}] — 命中 {len(all_results)} 条引用:\033[0m")

        # 按目标字符串分组展示
        by_target: dict = {}
        for r in all_results:
            by_target.setdefault(r.target_content, []).append(r)

        shown = 0
        for target_str, results in sorted(by_target.items()):
            if shown >= 60:
                print(f"\033[90m    ... 还有更多结果，请使用更精确的搜索词。\033[0m")
                break
            # 目标字符串摘要（截断显示）
            display = target_str[:80].replace("\n", "\\n")
            print(f"\n\033[1;32m  → \"{display}\"\033[0m  \033[90m({len(results)} 处引用)\033[0m")
            for r in results[:8]:
                func_label = f"func@{r.caller_func_hex}"
                print(f"      \033[96m{func_label}\033[0m  \033[90m指令偏移: {r.caller_hex}  [{r.instr_type}]\033[0m")
            if len(results) > 8:
                print(f"      \033[90m... 还有 {len(results) - 8} 处引用\033[0m")
            shown += 1

        total_hits += len(all_results)

    print("\n" + "-" * 80)
    print(f"\033[1m  总计命中: {total_hits} 条交叉引用\033[0m")
    print("=" * 80 + "\n")


def handle_disasm(pkg_info, target: str, count: int = 40):
    """提取并格式化打印 ARM64 函数汇编指令片段"""
    from analyzer.disassembler import Disassembler

    targets = ([pkg_info.main_binary] if pkg_info.main_binary else []) + pkg_info.frameworks

    print("\n" + "=" * 80)
    print(f"\033[1;35m[+] ARM64 精准反汇编 (Disassembler Bridge) — 目标: '{target}' (上限: {count} 条指令)\033[0m")
    print("=" * 80)

    total_funcs = 0
    for bin_info in targets:
        if not bin_info:
            continue

        dis = Disassembler(bin_info.abs_path)
        resolved_list = dis.resolve_target(target)
        if not resolved_list:
            continue

        print(f"\n\033[93m  [{bin_info.name}] — 解析出 {len(resolved_list)} 个目标函数入口:\033[0m")
        for label, va in resolved_list[:10]:
            print()
            func_block = dis.disasm_at(va, max_instructions=count)
            if "xref-caller" in label:
                func_block.title = label
            print(func_block.format_code(color=True))
            total_funcs += 1

        if len(resolved_list) > 10:
            print(f"\n\033[90m  ... 还有 {len(resolved_list) - 10} 个目标函数，请使用更精确的搜索词或十六进制偏移。\033[0m")

    if total_funcs == 0:
        print(f"\033[90m  未在任何二进制中解析到与 '{target}' 对应的有效函数入口或交叉引用调用者。\033[0m")
    print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    main()
