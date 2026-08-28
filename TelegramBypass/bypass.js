/*
 * Frida Dynamic Bypass Script for ph.telegra.Telegraph
 * Generated automatically by analyze.py / TweakGenerator
 * Usage: frida -U -f ph.telegra.Telegraph -l bypass.js
 */

(function() {
    console.log('[*] [Frida] === 正在注入自动化安全防护 Bypass 脚本 ===');

    // 2. [AD-002] sysctl P_TRACED 标志位清除
    const sysctlPtr = Module.findExportByName(null, 'sysctl');
    if (sysctlPtr) {
        Interceptor.attach(sysctlPtr, {
            onEnter: function(args) {
                this.name = args[0];
                this.namelen = args[1].toInt32();
                this.oldp = args[2];
            },
            onLeave: function(retval) {
                if (this.name && this.namelen >= 4 && !this.oldp.isNull()) {
                    const name0 = this.name.readInt();
                    const name1 = this.name.add(4).readInt();
                    const name2 = this.name.add(8).readInt();
                    if (name0 === 1 /* CTL_KERN */ && name1 === 14 /* KERN_PROC */ && name2 === 1 /* KERN_PROC_PID */) {
                        const p_flag_offset = 32; // arm64 kinfo_proc p_flag 偏移
                        const p_flag = this.oldp.add(p_flag_offset).readInt();
                        const P_TRACED = 0x00000800;
                        if ((p_flag & P_TRACED) !== 0) {
                            this.oldp.add(p_flag_offset).writeInt(p_flag & ~P_TRACED);
                            console.log('[+] [Anti-Debug] 清除 sysctl 中的 P_TRACED 标志位');
                        }
                    }
                }
            }
        });
    }

    // 4. [JB-001] 越狱文件与路径探测拦截 (stat / lstat / access / open)
    const jbPaths = [
        '/Applications/Cydia.app', '/Applications/Sileo.app', '/Applications/Zebra.app',
        '/Library/MobileSubstrate', '/usr/sbin/sshd', '/bin/bash', '/bin/sh', '/etc/apt',
        '/var/jb/', '/private/var/lib/cydia', 'libjailbreak.dylib', 'ElleKit'
    ];
    function isJb(path) {
        if (!path) return false;
        for (let p of jbPaths) {
            if (path.indexOf(p) !== -1) return true;
        }
        return false;
    }

    ['stat', 'lstat', 'access'].forEach(fn => {
        const ptr = Module.findExportByName(null, fn);
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter: function(args) {
                    try {
                        const path = args[0].readUtf8String();
                        if (isJb(path)) {
                            this.isJb = true;
                        }
                    } catch(e) {}
                },
                onLeave: function(retval) {
                    if (this.isJb) {
                        retval.replace(-1);
                    }
                }
            });
        }
    });

    if (ObjC.available) {
        try {
            const NSFileManager = ObjC.classes.NSFileManager;
            Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
                onEnter: function(args) {
                    const path = ObjC.Object(args[2]).toString();
                    if (isJb(path)) {
                        this.isJb = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.isJb) {
                        retval.replace(0);
                    }
                }
            });
        } catch(e) {}
    }

    // 5. [JB-002] canOpenURL 越狱 Scheme 拦截
    if (ObjC.available) {
        try {
            const UIApplication = ObjC.classes.UIApplication;
            Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
                onEnter: function(args) {
                    const url = ObjC.Object(args[2]).toString().toLowerCase();
                    if (url.startsWith('cydia:') || url.startsWith('sileo:') || url.startsWith('zbra:') || url.startsWith('filza:')) {
                        console.log('[+] [Jailbreak] 拦截 canOpenURL: ' + url);
                        this.blocked = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.blocked) {
                        retval.replace(0);
                    }
                }
            });
        } catch(e) {}
    }

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
