#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iOS Tweak 越狱插件与 Frida 脚本自动化生成工具 (Tweak & Bypass Generator)
基于 analyze.py 静态扫描分析结果，自动针对目标 IPA 组装生成开箱即用的 Theos Tweak 工程与 Frida Bypass 脚本。

使用示例:
  python3 gen_tweak.py -f target.ipa
  python3 gen_tweak.py -f target.ipa -o ./MyCustomTweak
  python3 gen_tweak.py -f target.ipa --all
  python3 gen_tweak.py -f target.ipa --rootful
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import (
    IPAParser,
    AnalysisEngine,
    TweakGenerator
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="iOS Tweak 越狱插件与 Frida 动态脚本自动化生成工具 (基于静态分析结果精准定制)",
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
        dest="output_dir",
        default=None,
        help="生成的 Theos Tweak 插件工程目录 (默认: ./<TargetAppName>Bypass)"
    )
    parser.add_argument(
        "--name",
        dest="tweak_name",
        default=None,
        help="自定义 Tweak 插件名称"
    )
    parser.add_argument(
        "--author",
        dest="author",
        default="SecurityResearcher",
        help="插件作者名称 (默认: SecurityResearcher)"
    )
    parser.add_argument(
        "--rootless",
        dest="rootless",
        action="store_true",
        default=True,
        help="生成 Rootless / Dopamine / Palera1n 架构的 Theos 配置 (默认启用)"
    )
    parser.add_argument(
        "--rootful",
        dest="rootless",
        action="store_false",
        help="生成传统 Rootful 越狱架构的 Theos 配置"
    )
    parser.add_argument(
        "--all",
        dest="force_all",
        action="store_true",
        help="生成全量 Bypass 规则库 (忽略静态检测结果，嵌入所有反调试、越狱、SSL固定、Frida检测规则)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    target_path = os.path.abspath(args.target_file)
    if not os.path.exists(target_path):
        print(f"\033[91m[-] 错误: 目标文件或目录不存在: {target_path}\033[0m", file=sys.stderr)
        sys.exit(1)

    print(f"\033[94m[*] 正在解析并扫描分析目标 IPA: {os.path.basename(target_path)} ...\033[0m")
    start_time = time.time()

    ipa_parser = IPAParser(target_path)
    try:
        # 1. 静态解析
        pkg_info = ipa_parser.parse()
        engine = AnalysisEngine(pkg_info)
        result = engine.run()

        # 2. 计算输出目录
        app_name = pkg_info.executable_name or pkg_info.bundle_name or "App"
        out_dir = args.output_dir or f"./{app_name}Bypass"
        out_dir = os.path.abspath(out_dir)

        print(f"\033[92m[+] 目标应用: {pkg_info.display_name or pkg_info.bundle_name} ({pkg_info.bundle_id})\033[0m")
        print(f"\033[94m[*] 检测到 {len(result.findings)} 项防护与安全特征，正在按需生成定制化的 Tweak 插件 ...\033[0m")

        # 3. 生成 Tweak 与 Frida 脚本
        generator = TweakGenerator(result, tweak_name=args.tweak_name, author=args.author)
        gen_files = generator.generate_project(
            output_dir=out_dir,
            rootless=args.rootless,
            force_all=args.force_all
        )

        elapsed = time.time() - start_time

        # 4. 打印生成结果面板
        print("\n" + "=" * 70)
        print(f"\033[1m\033[92m🎉 Tweak 插件工程与 Frida Bypass 脚本已成功生成!\033[0m")
        print("=" * 70)
        print(f"  • 输出目录         : \033[96m{out_dir}\033[0m")
        print(f"  • Tweak 插件源码   : \033[93m{os.path.basename(gen_files['tweak_x'])}\033[0m")
        print(f"  • Theos 构建配置   : \033[93m{os.path.basename(gen_files['makefile'])}\033[0m ({'Rootless' if args.rootless else 'Rootful'})")
        print(f"  • 进程过滤配置     : \033[93m{os.path.basename(gen_files['plist'])}\033[0m (Filter -> {pkg_info.bundle_id})")
        print(f"  • 包描述文件       : \033[93m{os.path.basename(gen_files['control'])}\033[0m")
        print(f"  • Frida 动态脚本   : \033[95m{os.path.basename(gen_files['frida_js'])}\033[0m (无需编译即可即时动态挂钩)")
        print("-" * 70)
        print(f"\033[1m[使用方式一: Theos 编译 deb 安装]\033[0m")
        print(f"  cd {out_dir}")
        print(f"  make package FINALPACKAGE=1")
        print(f"\n\033[1m[使用方式二: Frida 动态免编译即时加载]\033[0m")
        print(f"  cd {out_dir}")
        print(f"  frida -U -f {pkg_info.bundle_id or pkg_info.executable_name} -l bypass.js")
        print("=" * 70)
        print(f"\033[90m[*] 耗时: {elapsed:.2f} 秒\033[0m\n")

    except Exception as e:
        print(f"\033[91m[-] 生成过程发生异常: {str(e)}\033[0m", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        ipa_parser.cleanup()


if __name__ == "__main__":
    main()
