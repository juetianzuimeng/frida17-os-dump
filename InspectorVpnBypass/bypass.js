/*
 * Frida Dynamic Bypass Script for com.github.zhkl0228.inspector.vpn
 * Generated automatically by analyze.py / TweakGenerator
 * Usage: frida -U -f com.github.zhkl0228.inspector.vpn -l bypass.js
 */

(function() {
    console.log('[*] [Frida] === 正在注入自动化安全防护 Bypass 脚本 ===');

    // 7. [FH-001] Frida 默认端口扫描拦截 (27042, 27043, 23924, 23946)
    const connectPtr = Module.findExportByName(null, 'connect');
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function(args) {
                const addr = args[1];
                if (!addr.isNull()) {
                    const family = addr.add(1).readU8(); // sa_family
                    if (family === 2 /* AF_INET */) {
                        const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
                        if (port === 27042 || port === 27043 || port === 23924 || port === 23946) {
                            console.log('[+] [Frida-Detect] 拦截向 Frida 端口 ' + port + ' 的连接探测');
                            this.blocked = true;
                        }
                    }
                }
            },
            onLeave: function(retval) {
                if (this.blocked) {
                    retval.replace(-1);
                }
            }
        });
    }

    console.log('[*] [Frida] === Bypass 脚本挂钩全部就绪 ===');
})();
