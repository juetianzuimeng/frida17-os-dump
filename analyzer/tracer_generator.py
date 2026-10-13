# -*- coding: utf-8 -*-
"""
Frida 动态追踪探针生成器 (Dynamic Tracer Generator)

将静态分析挖掘出的函数偏移 (Offset)、符号或 Xref 调用点，
一键转化为可直接上机运行的高性能 Frida Hook 脚本。
具备自动 ASLR 寻址、入参智能嗅探 (String/ObjC/HexDump)、
精确调用栈打印 (Thread.backtrace) 与耗时监控。
"""

import os
from typing import Dict, List, Optional, Tuple


class TracerGenerator:
    """Frida 动态探针脚本生成器"""

    @classmethod
    def generate_script(
        cls,
        module_name: str,
        targets: List[Tuple[str, int]],  # [(label, offset)]
        include_backtrace: bool = True,
        max_hexdump_bytes: int = 32
    ) -> str:
        """生成完整的 Frida Hook JS 脚本"""
        hooks_js = []
        bt_snippet = ""
        if include_backtrace:
            bt_snippet = """
                // 打印调用栈
                console.log("   --- 📚 Call Stack ---");
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(s => "     " + s).join("\\n"));"""

        for label, offset in targets:
            offset_hex = hex(offset)
            hook_snippet = f"""
    // ------------------------------------------------------------------------
    // Target: {label} (Offset: {offset_hex})
    // ------------------------------------------------------------------------
    (function() {{
        const targetOffset = ptr("{offset_hex}");
        const targetAddress = base.add(targetOffset);

        Interceptor.attach(targetAddress, {{
            onEnter: function(args) {{
                this.startTime = Date.now();
                this.threadId = Process.getCurrentThreadId();

                console.log("\\n" + "=".repeat(70));
                console.log("[🎯 ENTER] {label} at " + targetAddress + " (tid: " + this.threadId + ")");

                // 打印前 6 个寄存器入参 (x0 ~ x5)
                for (let i = 0; i < 6; i++) {{
                    const val = args[i];
                    const info = inspectArg(val);
                    console.log("   arg[" + i + "]: " + val + "  " + info);
                }}
{bt_snippet}
            }},
            onLeave: function(retval) {{
                const elapsed = Date.now() - this.startTime;
                const retInfo = inspectArg(retval);
                console.log("[🏁 LEAVE] {label} -> " + retval + "  " + retInfo + " (耗时: " + elapsed + "ms)");
                console.log("=".repeat(70));
            }}
        }});
        console.log("[+] Hook installed: {label} @ " + targetAddress);
    }})();
"""
            hooks_js.append(hook_snippet)

        script = f"""/**
 * ============================================================================
 * Frida Dynamic Trace Script - 自动派生探针
 * 生成源: frida-ios-dump 静态分析引擎
 * 目标模块: {module_name}
 * 监听目标数: {len(targets)} 个
 * 使用命令: frida -U -f <BundleID> -l this_script.js --no-pause
 * ============================================================================
 */

(function() {{
    'use strict';

    const MODULE_NAME = "{module_name}";
    const mod = Process.findModuleByName(MODULE_NAME) || Process.enumerateModules()[0];
    if (!mod) {{
        console.error("[-] 未能定位目标模块: " + MODULE_NAME);
        return;
    }}
    const base = mod.base;
    console.log("[*] 成功锁定目标模块: " + mod.name + " (Base: " + base + ", Size: " + mod.size + ")");

    // 智能参数探测辅助函数 (String / ObjC / HexDump)
    function inspectArg(p) {{
        if (!p || p.isNull()) return "(null / 0)";
        try {{
            // 1. 判断是否为 ObjC 对象
            if (ObjC.available && ObjC.Object) {{
                try {{
                    const obj = ObjC.Object(p);
                    if (obj && obj.$className) {{
                        const desc = obj.toString ? obj.toString() : "";
                        return "[ObjC: " + obj.$className + "] " + desc.substring(0, 80);
                    }}
                }} catch (e) {{}}
            }}

            // 2. 尝试读取 UTF-8 字符串
            try {{
                const s = p.readUtf8String();
                if (s && s.length >= 2 && s.length <= 120 && /^[\x20-\x7E\s]+$/.test(s)) {{
                    return '[String] "' + s.replace(/\\n/g, "\\\\n") + '"';
                }}
            }} catch (e) {{}}

            // 3. 内存探测与 HexDump ({max_hexdump_bytes} 字节)
            const mem = p.readByteArray({max_hexdump_bytes});
            if (mem) {{
                const bytes = new Uint8Array(mem);
                const hexStr = Array.from(bytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
                return "[Mem: " + hexStr + "...]";
            }}
        }} catch (e) {{}}

        return "(scalar: " + p.toInt32() + ")";
    }}

    // ------------------------------------------------------------------------
    // 安装拦截探针
    // ------------------------------------------------------------------------
    {''.join(hooks_js)}

    console.log("[*] 所有动态探针安装完毕，等待目标函数触发...\\n");
}})();
"""
        return script
