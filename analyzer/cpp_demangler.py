# -*- coding: utf-8 -*-
"""
Itanium C++ ABI 符号反混淆与还原器 (C++ Demangler)

专用于解析与还原 iOS / macOS Mach-O 二进制中的 C++ 混淆符号（以 __Z 或 _Z 开头）。
具备：
1. 系统 c++filt 工具高性能管道批量还原（百微秒级/符号）
2. 纯 Python 轻量级 Itanium ABI 嵌套命名空间解析器（离线零环境兜底）
3. 内存级缓存加速 (LRU Cache)
"""

import os
import re
import shutil
import subprocess
from functools import lru_cache
from typing import Dict, List, Optional, Tuple


class CppDemangler:
    """Itanium C++ ABI 符号反混淆器"""

    _has_cxxfilt: Optional[bool] = None
    _cxxfilt_path: Optional[str] = None
    _cache: Dict[str, str] = {}

    @classmethod
    def _detect_tool(cls) -> bool:
        if cls._has_cxxfilt is not None:
            return cls._has_cxxfilt

        cxx_path = shutil.which("c++filt")
        if cxx_path and os.path.exists(cxx_path):
            cls._cxxfilt_path = cxx_path
            cls._has_cxxfilt = True
        else:
            cls._has_cxxfilt = False
        return cls._has_cxxfilt

    @classmethod
    def is_cpp_symbol(cls, sym: str) -> bool:
        """判断是否为 Itanium C++ Mangled 符号"""
        if not sym:
            return False
        clean = sym.strip()
        # Mach-O 中 C++ 符号通常以 __Z 或 _Z 开头
        return clean.startswith("__Z") or clean.startswith("_Z")

    @classmethod
    def demangle(cls, symbol: str) -> str:
        """还原单个 C++ 混淆符号"""
        if not symbol or not cls.is_cpp_symbol(symbol):
            return symbol

        sym = symbol.strip()
        if sym in cls._cache:
            return cls._cache[sym]

        # 1. 优先尝试系统 c++filt
        if cls._detect_tool():
            try:
                # LLVM c++filt 在 macOS 上需要 __Z 前缀
                norm_sym = sym if sym.startswith("__Z") else "_" + sym
                proc = subprocess.run(
                    [cls._cxxfilt_path, norm_sym],
                    capture_output=True,
                    text=True,
                    timeout=1.0,
                    check=False
                )
                if proc.returncode == 0:
                    out = proc.stdout.strip()
                    if out and out != norm_sym and out != sym:
                        cls._cache[sym] = out
                        return out
            except Exception:
                pass

        # 2. 纯 Python 离线轻量级解析兜底
        py_demangled = cls._pure_python_demangle(sym)
        if py_demangled and py_demangled != sym:
            cls._cache[sym] = py_demangled
            return py_demangled

        cls._cache[sym] = sym
        return sym

    @classmethod
    def demangle_batch(cls, symbols: List[str]) -> Dict[str, str]:
        """批量还原 C++ 符号列表"""
        results: Dict[str, str] = {}
        pending: List[str] = []

        for s in symbols:
            if not s:
                continue
            if not cls.is_cpp_symbol(s):
                results[s] = s
            elif s in cls._cache:
                results[s] = cls._cache[s]
            else:
                pending.append(s)

        if not pending:
            return results

        if cls._detect_tool():
            try:
                # 将所有符号整理为带 __Z 的格式
                norm_map = {}
                input_lines = []
                for s in pending:
                    norm = s if s.startswith("__Z") else "_" + s
                    norm_map[norm] = s
                    input_lines.append(norm)

                payload = "\n".join(input_lines)
                proc = subprocess.run(
                    [cls._cxxfilt_path],
                    input=payload,
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                    check=False
                )
                if proc.returncode == 0:
                    out_lines = proc.stdout.splitlines()
                    for norm, out in zip(input_lines, out_lines):
                        orig = norm_map.get(norm, norm)
                        final = out.strip() if out.strip() else orig
                        cls._cache[orig] = final
                        results[orig] = final
            except Exception:
                pass

        # 对未命中的继续走纯 Python 兜底
        for s in pending:
            if s not in results:
                res = cls.demangle(s)
                results[s] = res

        return results

    @classmethod
    def _pure_python_demangle(cls, sym: str) -> str:
        """
        纯 Python 解析 Itanium ABI 嵌套命名空间与函数名。
        处理: _ZN <len><name> ... <len><func> E <params>
        """
        raw = sym.lstrip("_")
        if not raw.startswith("Z"):
            return sym

        body = raw[1:]  # 去掉 'Z'

        # 嵌套名称: N ... E
        if body.startswith("N"):
            body = body[1:]
            parts = []
            idx = 0
            while idx < len(body):
                if body[idx] == "E":
                    # 命名空间结束
                    idx += 1
                    break

                # 提取长度数字
                num_match = re.match(r"^(\d+)", body[idx:])
                if num_match:
                    length = int(num_match.group(1))
                    start = idx + len(num_match.group(1))
                    name = body[start : start + length]
                    parts.append(name)
                    idx = start + length
                elif body[idx : idx + 2] == "C1" or body[idx : idx + 2] == "C2":
                    # 构造函数
                    if parts:
                        parts.append(parts[-1])
                    idx += 2
                elif body[idx : idx + 2] == "D1" or body[idx : idx + 2] == "D2":
                    # 析构函数
                    if parts:
                        parts.append("~" + parts[-1])
                    idx += 2
                elif body[idx : idx + 3] == "St3__1":
                    # std::__1
                    parts.append("std::__1")
                    idx += 6
                else:
                    # 遇到未知修饰符，停止解析嵌套名
                    break

            if parts:
                base_name = "::".join(parts)
                # 剩余部分为参数类型简易提示
                return f"{base_name}(...)"

        return sym
