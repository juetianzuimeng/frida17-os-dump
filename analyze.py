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
        "--callers",
        dest="callers_target",
        default=None,
        help="分析 ARM64 函数调用图：查找谁调用了目标函数 (如: --callers 0x47A68)"
    )
    parser.add_argument(
        "--callees",
        dest="callees_target",
        default=None,
        help="分析 ARM64 函数调用图：查找目标函数内部调用了哪些子函数 (如: --callees 0x746D90)"
    )
    parser.add_argument(
        "--gen-trace",
        dest="gen_trace_targets",
        default=None,
        help="一键派生 Frida 动态追踪探针脚本 (支持逗号分隔多个偏移/符号，如: --gen-trace 0x746D90 或 --gen-trace 0x47A68,0x746D90)"
    )
    parser.add_argument(
        "--trace-output",
        dest="trace_output_path",
        default=None,
        help="指定生成的 Frida 探针 JS 脚本保存路径 (未指定则默认在控制台输出)"
    )
    parser.add_argument(
        "--depth",
        dest="call_depth",
        type=int,
        default=1,
        help="指定函数调用图追溯的遍历深度 (默认: 1 层，可指定 2, 3 等多层递归展开)"
    )
    parser.add_argument(
        "--export-mermaid",
        dest="export_mermaid_path",
        default=None,
        help="将函数调用拓扑树导出为 Markdown Mermaid 流程图文件 (例如: callgraph.md)"
    )
    parser.add_argument(
        "--gen-sig",
        dest="gen_sig_target",
        default=None,
        help="提取跨版本鲁棒特征码 (Pattern Signature) (如: --gen-sig 0x746D90)"
    )
    parser.add_argument(
        "--find-sig",
        dest="find_sig_pattern",
        default=None,
        help="在目标二进制中检索特征码 (支持 '??' 通配符) (如: --find-sig 'FD 7B BE A9 ?? ?? ?? ?? E0 03 18 AA')"
    )
    parser.add_argument(
        "--cfg",
        dest="cfg_target",
        default=None,
        help="生成指定函数的 ARM64 控制流图 (CFG) 与基本块切分分析 (如: --cfg 0x908bc)"
    )
    parser.add_argument(
        "--export-cfg",
        dest="export_cfg_path",
        default=None,
        help="将函数控制流图 (CFG) 导出为 Markdown Mermaid 流程图文件 (例如: cfg.md)"
    )
    parser.add_argument(
        "--patch",
        dest="patch_specs",
        default=None,
        help="对指定目标执行 ARM64 指令热修补 (如: --patch 0x1E9B34:NOP 或 0x47A68:RET_TRUE)"
    )
    parser.add_argument(
        "--patch-output",
        dest="patch_output_file",
        default=None,
        help="指定打好静态补丁的新二进制文件输出路径 (未指定则默认保存为 <file>.patched)"
    )
    parser.add_argument(
        "--patch-script",
        dest="patch_script_file",
        default=None,
        help="导出免修改原文件的 Frida 运行时内存热补丁 JS 脚本路径 (如: mem_patch.js)"
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

    # 独立 Swift / C++ 符号还原工具模式
    if args.demangle_symbol is not None:
        from analyzer.demangler import UniversalDemangler, SwiftDemangler
        from analyzer.cpp_demangler import CppDemangler

        sym = args.demangle_symbol.strip()
        if not sym:
            print("[\033[31m!\033[0m] 请输入要还原的符号，例如: python3 analyze.py --demangle _TtC10Calculator16CalculatorLayout 或 python3 analyze.py --demangle __ZN11reliability16MmappedFilePosix12openExistingEPKcPS2_Pibb")
            sys.exit(1)

        kind = "Swift" if SwiftDemangler.is_swift_symbol(sym) else ("C++ (Itanium)" if CppDemangler.is_cpp_symbol(sym) else "通用")
        dem = UniversalDemangler.demangle(sym)
        print(f"\n\033[1;32m[+] 符号反混淆还原 [{kind}] (Demangled):\033[0m")
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

        # 3.8. 函数调用图分析 (Call Graph: Callers & Callees)
        if args.callers_target:
            handle_call_graph(pkg_info, mode="callers", target=args.callers_target, depth=args.call_depth, export_mermaid=args.export_mermaid_path)
        if args.callees_target:
            handle_call_graph(pkg_info, mode="callees", target=args.callees_target, depth=args.call_depth, export_mermaid=args.export_mermaid_path)

        # 3.9. Frida 动态追踪探针一键派生
        if args.gen_trace_targets:
            handle_gen_trace(pkg_info, args.gen_trace_targets, args.trace_output_path)

        # 3.10. 跨版本特征码制作与检索
        if args.gen_sig_target:
            handle_gen_sig(pkg_info, args.gen_sig_target)
        if args.find_sig_pattern:
            handle_find_sig(pkg_info, args.find_sig_pattern)

        # 3.11. 控制流图 (CFG) 分析与 Mermaid 导出
        if args.cfg_target:
            handle_cfg(pkg_info, args.cfg_target, args.export_cfg_path)

        # 3.12. 指令静态热修补与 Frida 内存 Patch 派生
        if args.patch_specs:
            handle_patch(pkg_info, args.patch_specs, args.patch_output_file, args.patch_script_file)

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


def handle_call_graph(pkg_info, mode: str, target: str, depth: int = 1, export_mermaid: str = None):
    """分析 ARM64 函数调用图 (Callers 或 Callees)，支持多级深度展开与 Mermaid 可视化导出"""
    from analyzer.call_graph import CallGraphAnalyzer
    from analyzer.disassembler import Disassembler

    targets = ([pkg_info.main_binary] if pkg_info.main_binary else []) + pkg_info.frameworks
    mode_name = "上游调用者 (Callers)" if mode == "callers" else "下游子调用 (Callees)"

    print("\n" + "=" * 80)
    print(f"\033[1;34m[+] ARM64 函数调用图分析 ({mode_name}) — 目标: '{target}' (遍历深度: {depth} 层)\033[0m")
    print("=" * 80)

    total_edges = 0
    mermaid_charts = []

    for bin_info in targets:
        if not bin_info:
            continue

        cg = CallGraphAnalyzer(bin_info.abs_path)
        dis = Disassembler(bin_info.abs_path)

        resolved_list = dis.resolve_target(target)
        if not resolved_list:
            continue

        for label, va in resolved_list[:5]:
            if depth > 1:
                # 多级深度树状展示
                tree = cg.build_call_tree(va, mode=mode, max_depth=depth)
                if not tree.children:
                    continue
                print(f"\n\033[93m  [{bin_info.name}]\033[0m \033[1;32m→ 多级调用拓扑树 (Depth: {depth}):\033[0m")
                for line in CallGraphAnalyzer.format_console_tree(tree):
                    print(f"    {line}")
                total_edges += len(tree.children)

                if export_mermaid:
                    chart = CallGraphAnalyzer.format_mermaid(tree, mode=mode, title=f"{bin_info.name} - {label} ({mode})")
                    mermaid_charts.append(chart)
            else:
                # 单级平铺展示
                if mode == "callers":
                    edges = cg.get_callers(va)
                    if not edges:
                        continue
                    print(f"\n\033[93m  [{bin_info.name}]\033[0m \033[1;32m→ 目标函数: func@0x{va:X} ({label})\033[0m  \033[90m(发现 {len(edges)} 处调用来源)\033[0m")
                    for i, edge in enumerate(edges[:30], 1):
                        delta = edge.call_site_va - edge.caller_va
                        delta_str = f"+0x{delta:X}" if delta >= 0 else f"-0x{-delta:X}"
                        print(
                            f"      \033[96m[{i:02d}] func@0x{edge.caller_va:X}\033[0m"
                            f"  \033[90m(指令地址: 0x{edge.call_site_va:X}, 偏移动态: {delta_str})\033[0m"
                            f"  \033[1;33mBL -> 0x{edge.target_va:X}\033[0m"
                        )
                    if len(edges) > 30:
                        print(f"      \033[90m... 还有 {len(edges) - 30} 处调用来源未列出\033[0m")
                    total_edges += len(edges)
                else:
                    edges = cg.get_callees(va, from_exact_addr=True)
                    if not edges:
                        edges = cg.get_callees(va, from_exact_addr=False)
                    if not edges:
                        continue
                    print(f"\n\033[93m  [{bin_info.name}]\033[0m \033[1;32m→ 目标函数/位置: 0x{va:X} ({label})\033[0m  \033[90m(探测到 {len(edges)} 处子调用)\033[0m")
                    for i, edge in enumerate(edges[:30], 1):
                        delta = edge.call_site_va - edge.caller_va
                        delta_str = f"+0x{delta:X}" if delta >= 0 else f"-0x{-delta:X}"
                        print(
                            f"      \033[96m[{i:02d}] 指令 0x{edge.call_site_va:X} ({delta_str})\033[0m"
                            f"  \033[1;33mBL -> func@0x{edge.target_va:X}\033[0m"
                        )
                    if len(edges) > 30:
                        print(f"      \033[90m... 还有 {len(edges) - 30} 处子调用未列出\033[0m")
                    total_edges += len(edges)

                if export_mermaid:
                    tree = cg.build_call_tree(va, mode=mode, max_depth=1)
                    chart = CallGraphAnalyzer.format_mermaid(tree, mode=mode, title=f"{bin_info.name} - {label} ({mode})")
                    mermaid_charts.append(chart)

    if export_mermaid and mermaid_charts:
        out_p = os.path.abspath(export_mermaid)
        os.makedirs(os.path.dirname(out_p), exist_ok=True) if os.path.dirname(out_p) else None
        with open(out_p, "w", encoding="utf-8") as f:
            f.write("# 函数调用拓扑 Mermaid 流程图\n\n" + "\n\n".join(mermaid_charts))
        print(f"\n\033[1;32m[+] 调用拓扑 Mermaid 流程图已成功保存至: {out_p}\033[0m")

    if total_edges == 0:
        print(f"\033[90m  未在二进制中检测到与 '{target}' 相关的有效调用边。\033[0m")
    print("\n" + "=" * 80 + "\n")


def handle_gen_trace(pkg_info, targets_str: str, output_path: str = None):
    """一键生成 Frida 动态追踪探针脚本"""
    from analyzer.tracer_generator import TracerGenerator
    from analyzer.disassembler import Disassembler

    targets = ([pkg_info.main_binary] if pkg_info.main_binary else []) + pkg_info.frameworks
    raw_targets = [t.strip() for t in targets_str.split(",") if t.strip()]

    print("\n" + "=" * 80)
    print(f"\033[1;32m[+] Frida 动态追踪探针一键派生 (Dynamic Tracer Generator)\033[0m")
    print(f"  目标列表: {raw_targets}")
    print("=" * 80)

    module_targets = {}

    for bin_info in targets:
        if not bin_info:
            continue
        dis = Disassembler(bin_info.abs_path)
        for t in raw_targets:
            resolved = dis.resolve_target(t)
            for label, va in resolved:
                base = dis._image_base or 0x100000000
                rva = va - base if va >= base else va
                module_targets.setdefault(bin_info.name, []).append((label, rva))

    if not module_targets:
        primary_mod = pkg_info.executable_name or (pkg_info.main_binary.name if pkg_info.main_binary else "App")
        fallback_list = []
        for t in raw_targets:
            try:
                val = int(t, 16) if t.lower().startswith("0x") else int(t, 16)
                fallback_list.append((f"sub_{val:X}", val))
            except ValueError:
                pass
        if fallback_list:
            module_targets[primary_mod] = fallback_list

    if not module_targets:
        print(f"\033[91m[-] 无法解析输入的目标: {targets_str}\033[0m")
        return

    combined_scripts = []
    for mod_name, trace_list in module_targets.items():
        seen_rvas = set()
        deduped = []
        for lbl, rva in trace_list:
            if rva not in seen_rvas:
                seen_rvas.add(rva)
                deduped.append((lbl, rva))

        print(f"\n  \033[94m[*] 模块 [{mod_name}]: 锁定 {len(deduped)} 个拦截探针\033[0m")
        for lbl, rva in deduped:
            print(f"      → \033[96m{lbl}\033[0m (Offset: \033[1;33m0x{rva:X}\033[0m)")

        js = TracerGenerator.generate_script(mod_name, deduped)
        combined_scripts.append(js)

    full_script = "\n\n".join(combined_scripts)

    if output_path:
        out_p = os.path.abspath(output_path)
        out_dir = os.path.dirname(out_p)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(full_script)
        print(f"\n\033[1;32m[+] 探针脚本已成功导出至: {out_p}\033[0m")
        bundle_id = pkg_info.bundle_id or "<BundleID>"
        print(f"  \033[93m建议启动命令:\033[0m")
        print(f"    \033[1mfrida -U -f {bundle_id} -l {output_path} --no-pause\033[0m\n")
    else:
        print("\n" + "-" * 80)
        print("\033[90m// Frida 探针 JS 脚本代码 (可保存为 .js 使用):\033[0m\n")
        print(full_script)
        print("-" * 80 + "\n")


def handle_gen_sig(pkg_info, target_str: str):
    """为指定函数提取跨版本鲁棒特征码 (Pattern Signature)"""
    from analyzer.sig_maker import SigMaker
    from analyzer.disassembler import Disassembler

    targets = ([pkg_info.main_binary] if pkg_info.main_binary else []) + pkg_info.frameworks

    print("\n" + "=" * 80)
    print(f"\033[1;35m[+] ARM64 函数跨版本特征码制作 (SigMaker) — 目标: '{target_str}'\033[0m")
    print("=" * 80)

    found = 0
    for bin_info in targets:
        if not bin_info:
            continue
        sm = SigMaker(bin_info.abs_path)
        dis = Disassembler(bin_info.abs_path)

        resolved_list = dis.resolve_target(target_str)
        if not resolved_list:
            continue

        for label, va in resolved_list[:3]:
            pat, mask, count = sm.generate_signature(va)
            if not pat:
                continue

            print(f"\n  \033[93m[{bin_info.name}]\033[0m \033[1;32m→ 目标: func@0x{va:X} ({label})\033[0m")
            print(f"      \033[94m[IDA / YARA Pattern]:\033[0m  \033[1m{pat}\033[0m")
            print(f"      \033[90m[Mask String]:\033[0m         {mask}")
            print(f"      \033[90m[当前包匹配数]:\033[0m       {count} 处 ({'唯一精准匹配' if count == 1 else '多处匹配'})")
            found += 1

    if found == 0:
        print(f"\033[90m  未能解析目标地址或提取到有效特征码。\033[0m")
    print("\n" + "=" * 80 + "\n")


def handle_find_sig(pkg_info, pattern: str):
    """在目标二进制中检索特征码并定位函数"""
    from analyzer.sig_maker import SigMaker

    targets = ([pkg_info.main_binary] if pkg_info.main_binary else []) + pkg_info.frameworks

    print("\n" + "=" * 80)
    print(f"\033[1;32m[+] ARM64 跨版本特征码检索 (Pattern Matcher) — 模式: '{pattern}'\033[0m")
    print("=" * 80)

    total_hits = 0
    for bin_info in targets:
        if not bin_info:
            continue
        sm = SigMaker(bin_info.abs_path)
        matches = sm.find_signature(pattern)
        if not matches:
            continue

        print(f"\n  \033[93m[{bin_info.name}]\033[0m 命中 \033[1;32m{len(matches)}\033[0m 处位置:")
        for i, m in enumerate(matches[:10], 1):
            print(
                f"      \033[96m[{i:02d}] 虚拟地址 (VA): 0x{m.va:X}\033[0m"
                f"  \033[90m(文件偏移: 0x{m.file_offset:X})\033[0m"
                f"  \033[1;33mHex: {m.matched_hex[:36]}...\033[0m"
            )
        if len(matches) > 10:
            print(f"      \033[90m... 还有 {len(matches) - 10} 处匹配未列出\033[0m")
        total_hits += len(matches)

    if total_hits == 0:
        print(f"\033[90m  未在二进制中匹配到该特征码。\033[0m")
    print("\n" + "=" * 80 + "\n")


def handle_cfg(pkg_info, target_str: str, export_path: str = None):
    """分析 ARM64 函数控制流图 (CFG) 并可导出 Mermaid 流程图"""
    from analyzer.cfg_analyzer import CFGAnalyzer
    from analyzer.disassembler import Disassembler

    targets = ([pkg_info.main_binary] if pkg_info.main_binary else []) + pkg_info.frameworks

    print("\n" + "=" * 80)
    print(f"\033[1;35m[+] ARM64 函数控制流图分析 (CFG) — 目标: '{target_str}'\033[0m")
    print("=" * 80)

    found = 0
    mermaid_charts = []

    for bin_info in targets:
        if not bin_info:
            continue
        cfg_an = CFGAnalyzer(bin_info.abs_path)
        dis = Disassembler(bin_info.abs_path)

        resolved_list = dis.resolve_target(target_str)
        if not resolved_list:
            continue

        for label, va in resolved_list[:3]:
            cfg = cfg_an.analyze_function(va)
            if not cfg.blocks:
                continue

            print(f"\n  \033[93m[{bin_info.name}]\033[0m \033[1;32m→ 控制流图:\033[0m")
            for line in CFGAnalyzer.format_console_cfg(cfg):
                print(f"    {line}")
            found += 1

            if export_path:
                chart = CFGAnalyzer.format_mermaid_cfg(cfg)
                mermaid_charts.append(chart)

    if export_path and mermaid_charts:
        out_p = os.path.abspath(export_path)
        out_dir = os.path.dirname(out_p)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write("# 函数控制流图 (CFG) Mermaid 流程图\n\n" + "\n\n".join(mermaid_charts))
        print(f"\n\033[1;32m[+] 控制流图 Mermaid 流程图已成功保存至: {out_p}\033[0m")

    if found == 0:
        print(f"\033[90m  未能解析目标地址或构建控制流图。\033[0m")
    print("\n" + "=" * 80 + "\n")


def handle_patch(pkg_info, patch_specs: str, patch_output: str = None, patch_script: str = None):
    """处理 ARM64 指令静态补丁与 Frida 动态内存热修补"""
    from analyzer.patcher import BinaryPatcher

    targets = ([pkg_info.main_binary] if pkg_info.main_binary else []) + pkg_info.frameworks
    spec_list = [s.strip() for s in patch_specs.split(",") if s.strip()]

    print("\n" + "=" * 80)
    print(f"\033[1;31m[+] ARM64 指令热修补与 Frida 运行时 Patch (Binary & Memory Patcher)\033[0m")
    print(f"  补丁任务列表: {spec_list}")
    print("=" * 80)

    for bin_info in targets:
        if not bin_info:
            continue
        patcher = BinaryPatcher(bin_info.abs_path)
        parsed_items = []
        for spec in spec_list:
            item = patcher.parse_patch_spec(spec)
            if item:
                parsed_items.append(item)

        if not parsed_items:
            continue

        print(f"\n  \033[93m[{bin_info.name}]\033[0m 锁定 \033[1;32m{len(parsed_items)}\033[0m 处有效修补点:")
        for i, item in enumerate(parsed_items, 1):
            orig_hex = " ".join(f"{b:02X}" for b in item.original_bytes)
            patch_hex = " ".join(f"{b:02X}" for b in item.patch_bytes)
            print(
                f"      \033[96m[{i:02d}] 目标: {item.target_raw}\033[0m  \033[90m(偏移: 0x{item.file_offset:X})\033[0m\n"
                f"          原始机器码: \033[91m{orig_hex}\033[0m\n"
                f"          替换机器码: \033[92m{patch_hex}\033[0m  \033[1;33m[{item.description}]\033[0m"
            )

        # 1. 执行静态二进制 Patch
        out_file, applied = patcher.apply_patch(parsed_items, output_path=patch_output)
        print(f"\n  \033[1;32m[✓] 静态修补二进制已保存至: {out_file}\033[0m")
        print(f"      \033[90m(原始文件已安全备份为: {bin_info.abs_path}.bak)\033[0m")

        # 2. 导出 Frida 内存热补丁脚本
        if patch_script:
            frida_js = patcher.generate_frida_patch_script(bin_info.name, applied)
            s_path = os.path.abspath(patch_script)
            os.makedirs(os.path.dirname(s_path), exist_ok=True) if os.path.dirname(s_path) else None
            with open(s_path, "w", encoding="utf-8") as f:
                f.write(frida_js)
            print(f"  \033[1;32m[✓] Frida 动态内存热补丁脚本已导出至: {s_path}\033[0m")
            bundle_id = pkg_info.bundle_id or "<BundleID>"
            print(f"      \033[93m建议启动命令:\033[0m \033[1mfrida -U -f {bundle_id} -l {patch_script} --no-pause\033[0m\n")


if __name__ == "__main__":
    main()
