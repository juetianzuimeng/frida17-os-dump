/*
 * Frida Dynamic Bypass Script for com.facebook.Messenger (增强网络监控与异常日志版)
 * Generated & Enhanced for Diagnostics and Network Failure Tracing
 * Usage: frida -U -f com.facebook.Messenger -l bypass.js
 */

(function() {
    console.log('[*] [Frida] === 正在注入自动化安全防护 Bypass 与网络监控脚本 ===');

    function logI(tag, msg) {
        console.log('[+] [' + tag + '] ' + msg);
    }
    function logW(tag, msg) {
        console.warn('[!] [' + tag + '] ' + msg);
    }
    function logE(tag, msg) {
        console.error('[-] [' + tag + '] ' + msg);
    }

    // ========================================================================
    // 1. 网络请求与异常失败深度监控 (NSURLSession & SSL Error Monitor)
    // ========================================================================
    if (ObjC.available) {
        try {
            const NSURLSession = ObjC.classes.NSURLSession;
            
            // Hook dataTaskWithRequest:completionHandler:
            if (NSURLSession['- dataTaskWithRequest:completionHandler:']) {
                Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
                    onEnter: function(args) {
                        try {
                            const req = ObjC.Object(args[2]);
                            const url = req.URL() ? req.URL().absoluteString().toString() : '(Unknown URL)';
                            const method = req.HTTPMethod() ? req.HTTPMethod().toString() : 'GET';
                            const origBlockPtr = args[3];

                            if (!origBlockPtr.isNull()) {
                                const origBlock = new ObjC.Block(origBlockPtr);
                                const origCallback = origBlock.implementation;

                                origBlock.implementation = function(data, response, error) {
                                    try {
                                        let statusCode = 0;
                                        if (response && !response.isNull()) {
                                            const respObj = ObjC.Object(response);
                                            if (respObj.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
                                                statusCode = respObj.statusCode();
                                            }
                                        }

                                        if (error && !error.isNull()) {
                                            const errObj = ObjC.Object(error);
                                            const code = errObj.code().valueOf();
                                            const domain = errObj.domain().toString();
                                            const desc = errObj.localizedDescription().toString();

                                            if (code === -1200 || code === -1202 || code === -1204 || code === -1205) {
                                                logE('NETWORK_SSL_FAIL', '🚨 [SSL Pinning 握手失败] URL: ' + url + ' | Code: ' + code + ' | Domain: ' + domain + ' | 原因: ' + desc);
                                                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
                                            } else {
                                                logE('NETWORK_ERROR', '❌ [网络请求失败] URL: ' + url + ' | Method: ' + method + ' | Error: [' + domain + ': ' + code + '] ' + desc);
                                            }
                                        } else if (statusCode >= 400) {
                                            logW('NETWORK_HTTP_ERR', '⚠️ [HTTP ' + statusCode + ' 异常状态] URL: ' + url + ' | Method: ' + method);
                                        } else {
                                            logI('NETWORK_OK', '✅ [HTTP ' + statusCode + ' 正常] URL: ' + url);
                                        }
                                    } catch(ex) {
                                        logE('NETWORK_HOOK_ERR', 'Completion handler error: ' + ex);
                                    }
                                    return origCallback(data, response, error);
                                };
                            }
                        } catch(e) {
                            logE('NETWORK_HOOK', 'Hook dataTask error: ' + e);
                        }
                    }
                });
            }
        } catch(e) {
            logE('NSURLSession_HOOK', 'Failed to hook NSURLSession: ' + e);
        }
    }

    // ========================================================================
    // 2. 反调试防护绕过 (Anti-Debug)
    // ========================================================================
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
                            logI('Anti-Debug', '清除 sysctl 中的 P_TRACED 标志位');
                        }
                    }
                }
            }
        });
    }

    // ========================================================================
    // 3. 越狱文件与路径探测拦截 (stat / lstat / access / open)
    // ========================================================================
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

    // canOpenURL 越狱 Scheme 拦截
    if (ObjC.available) {
        try {
            const UIApplication = ObjC.classes.UIApplication;
            Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
                onEnter: function(args) {
                    const url = ObjC.Object(args[2]).toString().toLowerCase();
                    if (url.startsWith('cydia:') || url.startsWith('sileo:') || url.startsWith('zbra:') || url.startsWith('filza:')) {
                        logI('Jailbreak', '拦截 canOpenURL: ' + url);
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

    // ========================================================================
    // 4. HTTPS 证书固定绕过 (SSL Pinning)
    // ========================================================================
    const secTrustErrPtr = Module.findExportByName(null, 'SecTrustEvaluateWithError');
    if (secTrustErrPtr) {
        Interceptor.attach(secTrustErrPtr, {
            onLeave: function(retval) {
                logI('SSL-Pinning', '放行 SecTrustEvaluateWithError');
                retval.replace(1);
            }
        });
    }
    const secTrustPtr = Module.findExportByName(null, 'SecTrustEvaluate');
    if (secTrustPtr) {
        Interceptor.attach(secTrustPtr, {
            onEnter: function(args) {
                this.result = args[1];
            },
            onLeave: function(retval) {
                if (!this.result.isNull()) {
                    this.result.writeInt(1); // kSecTrustResultProceed
                }
                retval.replace(0); // errSecSuccess
            }
        });
    }

    function hookMbedtls() {
        const mbedtlsPtr = Module.findExportByName(null, 'mbedtls_x509_crt_verify');
        if (mbedtlsPtr) {
            Interceptor.attach(mbedtlsPtr, {
                onEnter: function(args) {
                    this.flagsPtr = args[4];
                },
                onLeave: function(retval) {
                    if (this.flagsPtr && !this.flagsPtr.isNull()) {
                        this.flagsPtr.writeU32(0);
                    }
                    retval.replace(0);
                    logI('SSL-Pinning', '成功放行 mbedtls_x509_crt_verify');
                }
            });
        }
    }
    hookMbedtls();
    setTimeout(hookMbedtls, 1000);

    // ========================================================================
    // 5. Frida 默认端口扫描拦截 (27042, 27043, 23924, 23946)
    // ========================================================================
    const connectPtr = Module.findExportByName(null, 'connect');
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function(args) {
                const addr = args[1];
                if (!addr.isNull()) {
                    const family = addr.add(1).readU8();
                    if (family === 2 /* AF_INET */) {
                        const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
                        if (port === 27042 || port === 27043 || port === 23924 || port === 23946) {
                            logI('Frida-Detect', '拦截向 Frida 端口 ' + port + ' 的连接探测');
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

    logI('Frida', '=== Bypass 与 网络监控脚本挂钩全部就绪 ===');
})();
