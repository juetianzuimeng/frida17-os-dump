# -*- coding: utf-8 -*-
"""
Swift 符号还原器 (Swift Demangler)
支持自动检测系统 swift-demangle 工具与纯 Python 启发式解析回退。
能够将 _TtC10Calculator16CalculatorLayout 等 Swift 混淆类名与 $s / _$s 符号还原为人类可读的命名空间和函数签名。
"""

import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple


class SwiftDemangler:
    """Swift 符号反混淆与名称还原器"""

    _bin_path: Optional[str] = None
    _bin_checked: bool = False
    _cache: Dict[str, str] = {}

    @classmethod
    def find_tool(cls) -> Optional[str]:
        """定位系统环境中的 swift-demangle 路径"""
        if cls._bin_checked:
            return cls._bin_path

        cls._bin_checked = True

        # 1. 检查 PATH
        path_tool = shutil.which("swift-demangle")
        if path_tool and os.path.isfile(path_tool):
            cls._bin_path = path_tool
            return cls._bin_path

        # 2. 检查 Xcode toolchain 常见路径
        xcode_paths = [
            "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-demangle",
            "/Library/Developer/CommandLineTools/usr/bin/swift-demangle",
        ]
        for xp in xcode_paths:
            if os.path.isfile(xp) and os.access(xp, os.X_OK):
                cls._bin_path = xp
                return cls._bin_path

        # 3. 尝试 xcrun
        try:
            p = subprocess.run(
                ["xcrun", "--find", "swift-demangle"],
                capture_output=True,
                text=True,
                timeout=2
            )
            out = p.stdout.strip()
            if p.returncode == 0 and os.path.isfile(out):
                cls._bin_path = out
                return cls._bin_path
        except Exception:
            pass

        return None

    @classmethod
    def demangle(cls, symbol: str) -> str:
        """还原单个 Swift 符号"""
        if not symbol:
            return ""

        if symbol in cls._cache:
            return cls._cache[symbol]

        # 仅针对疑似 Swift 符号处理
        if not cls.is_swift_symbol(symbol):
            cls._cache[symbol] = symbol
            return symbol

        # 优先使用纯 Python 快速解码常见 ObjC 桥接类名 (_TtC...)
        py_res = cls.pure_python_demangle(symbol)
        if py_res and py_res != symbol:
            cls._cache[symbol] = py_res
            return py_res

        # 若纯 Python 未命中或属于复杂符号 ($s / _$s)，尝试外部 swift-demangle
        tool = cls.find_tool()
        if tool:
            try:
                p = subprocess.run(
                    [tool, "-compact", symbol],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if p.returncode == 0:
                    out = p.stdout.strip()
                    # 输出格式可能是 "symbol ---> demangled" 或直接 "demangled"
                    if "--->" in out:
                        out = out.split("--->", 1)[1].strip()
                    if out:
                        cls._cache[symbol] = out
                        return out
            except Exception:
                pass

        cls._cache[symbol] = symbol
        return symbol

    @classmethod
    def demangle_batch(cls, symbols: List[str]) -> Dict[str, str]:
        """批量还原 Swift 符号（高效管道处理）"""
        results: Dict[str, str] = {}
        pending_external: List[str] = []

        for sym in set(symbols):
            if not sym:
                continue
            if sym in cls._cache:
                results[sym] = cls._cache[sym]
                continue
            if not cls.is_swift_symbol(sym):
                results[sym] = sym
                cls._cache[sym] = sym
                continue

            # 尝试纯 Python 解析
            py_res = cls.pure_python_demangle(sym)
            if py_res and py_res != sym:
                results[sym] = py_res
                cls._cache[sym] = py_res
            else:
                pending_external.append(sym)

        # 外部批量调用
        tool = cls.find_tool()
        if tool and pending_external:
            try:
                input_data = "\n".join(pending_external)
                p = subprocess.run(
                    [tool, "-compact"],
                    input=input_data,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if p.returncode == 0:
                    lines = [line.strip() for line in p.stdout.splitlines()]
                    for orig, dem in zip(pending_external, lines):
                        if "--->" in dem:
                            dem = dem.split("--->", 1)[1].strip()
                        resolved = dem if dem else orig
                        results[orig] = resolved
                        cls._cache[orig] = resolved
            except Exception:
                for orig in pending_external:
                    results[orig] = orig
                    cls._cache[orig] = orig
        else:
            for orig in pending_external:
                results[orig] = orig
                cls._cache[orig] = orig

        return results

    @classmethod
    def is_swift_symbol(cls, symbol: str) -> bool:
        """判断符号是否具有 Swift 混淆特征"""
        if not symbol or len(symbol) < 3:
            return False
        return (
            symbol.startswith("_TtC") or
            symbol.startswith("_TtP") or
            symbol.startswith("_TtCs") or
            symbol.startswith("$s") or
            symbol.startswith("_$s") or
            symbol.startswith("$S") or
            symbol.startswith("_$S") or
            symbol.startswith("_T0") or
            symbol.startswith("__T0")
        )

    @classmethod
    def pure_python_demangle(cls, symbol: str) -> Optional[str]:
        """
        纯 Python 零依赖解析常见的 Swift-ObjC 类/协议前缀:
        _TtC<len1><Mod><len2><Class> -> Mod.Class
        _TtCs<len><Class>            -> Swift.Class
        _TtP<len1><Mod><len2><Proto> -> (Protocol) Mod.Proto
        """
        if not symbol:
            return None

        # 1. Swift 标准库特例 _TtCs
        if symbol.startswith("_TtCs"):
            rest = symbol[5:]
            m = re.match(r"^(\d+)([A-Za-z0-9_]+)", rest)
            if m:
                length = int(m.group(1))
                name = m.group(2)[:length]
                return f"Swift.{name}"

        # 2. 类 _TtC 或 协议 _TtP
        prefix = None
        if symbol.startswith("_TtC"):
            prefix = ""
            pos = 4
        elif symbol.startswith("_TtP"):
            prefix = "(protocol) "
            pos = 4
        else:
            return None

        parts = []
        s_len = len(symbol)
        while pos < s_len:
            # 匹配数字长度前缀
            m = re.match(r"^(\d+)", symbol[pos:])
            if not m:
                break
            num_str = m.group(1)
            chunk_len = int(num_str)
            pos += len(num_str)
            if pos + chunk_len > s_len:
                break
            part_name = symbol[pos:pos + chunk_len]
            parts.append(part_name)
            pos += chunk_len

        if parts:
            return prefix + ".".join(parts)

        return None
