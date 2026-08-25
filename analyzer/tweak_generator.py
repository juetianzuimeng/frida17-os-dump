# -*- coding: utf-8 -*-
"""
Theos Tweak 插件与 Frida Bypass 脚本自动化生成引擎
根据 IPA 静态分析命中的具体检测点，动态生成定制化的越狱插件与动态调试脚本。
"""

import os
import re
from typing import List, Set, Dict, Any, Optional
from .engine import AnalysisResult
from .rules.base import RuleCategory, Finding


class TweakGenerator:
    """Theos Tweak 与 Frida Bypass 脚本生成器"""

    def __init__(self, result: AnalysisResult, tweak_name: Optional[str] = None, author: str = "SecurityResearcher"):
        self.result = result
        self.pkg = result.package_info
        self.findings = result.findings
        self.author = author

        # 生成合法的 Tweak 英文标识名
        raw_name = tweak_name or self.pkg.executable_name or self.pkg.bundle_name or "AppBypass"
        # 移除非字母数字字符
        clean_name = re.sub(r"[^a-zA-Z0-9_]", "", raw_name)
        if not clean_name or not clean_name[0].isalpha():
            clean_name = "Bypass" + clean_name
        self.tweak_name = clean_name + "Bypass"

        # 收集命中的所有 rule_id
        self.hit_rule_ids: Set[str] = {f.rule_id for f in self.findings}

    def generate_project(self, output_dir: str, rootless: bool = True, force_all: bool = False) -> Dict[str, str]:
        """
        在指定输出目录生成完整的 Theos 插件工程文件
        返回生成的文件路径字典: {"tweak_x": ..., "makefile": ..., "plist": ..., "control": ..., "frida_js": ...}
        """
        os.makedirs(output_dir, exist_ok=True)

        # 1. 生成 Tweak.x (Logos 源码)
        tweak_x_content = self.generate_tweak_x(force_all=force_all)
        tweak_x_path = os.path.join(output_dir, "Tweak.x")
        with open(tweak_x_path, "w", encoding="utf-8") as f:
            f.write(tweak_x_content)

        # 2. 生成 Makefile
        makefile_content = self.generate_makefile(rootless=rootless)
        makefile_path = os.path.join(output_dir, "Makefile")
        with open(makefile_path, "w", encoding="utf-8") as f:
            f.write(makefile_content)

        # 3. 生成 <TweakName>.plist
        plist_content = self.generate_plist()
        plist_path = os.path.join(output_dir, f"{self.tweak_name}.plist")
        with open(plist_path, "w", encoding="utf-8") as f:
            f.write(plist_content)

        # 4. 生成 control
        control_content = self.generate_control(rootless=rootless)
        control_path = os.path.join(output_dir, "control")
        with open(control_path, "w", encoding="utf-8") as f:
            f.write(control_content)

        # 5. 生成 Frida 双模动态 Bypass 脚本 (bypass.js)
        frida_content = self.generate_frida_bypass(force_all=force_all)
        frida_path = os.path.join(output_dir, "bypass.js")
        with open(frida_path, "w", encoding="utf-8") as f:
            f.write(frida_content)

        # 6. 生成使用指南 README.md
        readme_content = self.generate_readme()
        readme_path = os.path.join(output_dir, "README.md")
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(readme_content)

        return {
            "tweak_x": tweak_x_path,
            "makefile": makefile_path,
            "plist": plist_path,
            "control": control_path,
            "frida_js": frida_path,
            "readme": readme_path
        }

    def generate_tweak_x(self, force_all: bool = False) -> str:
        """生成 Logos / C Hook 源码 (Tweak.x)"""
        hits = self.hit_rule_ids
        bundle_id = self.pkg.bundle_id or "com.target.app"
        app_name = self.pkg.display_name or self.pkg.bundle_name or "TargetApp"

        # 判断是否需要各个模块
        need_ptrace = force_all or "AD-001" in hits
        need_sysctl = force_all or "AD-002" in hits
        need_task_ports = force_all or "AD-003" in hits
        need_signal = force_all or "AD-004" in hits
        need_getppid = force_all or "AD-005" in hits
        need_dyld_env = force_all or "AD-006" in hits
        need_isatty = force_all or "AD-007" in hits

        need_jb_paths = force_all or "JB-001" in hits or "JB-006" in hits
        need_jb_scheme = force_all or "JB-002" in hits
        need_jb_sandbox = force_all or "JB-003" in hits
        need_jb_dyld = force_all or "JB-004" in hits
        need_jb_fork = force_all or "JB-005" in hits
        need_jb_suite = force_all or "JB-007" in hits

        need_ssl_trustkit = force_all or "SSL-001" in hits
        need_ssl_afn = force_all or "SSL-002" in hits
        need_ssl_alamofire = force_all or "SSL-003" in hits
        need_ssl_sectrust = force_all or "SSL-004" in hits
        need_ssl_delegate = force_all or "SSL-005" in hits

        need_frida_port = force_all or "FH-001" in hits
        need_frida_thread = force_all or "FH-003" in hits

        # 头部与头文件导入
        code = [
            "// ============================================================================",
            f"// {self.tweak_name} - 自动化生成的安全防护 Bypass 插件",
            f"// 目标应用: {app_name} ({bundle_id})",
            f"// 生成时间: {os.popen('date').read().strip()}",
            "// 基于 analyze.py 静态扫描分析结果精准定制生成",
            "// ============================================================================",
            "",
            "#import <Foundation/Foundation.h>",
            "#import <UIKit/UIKit.h>",
            "#import <sys/sysctl.h>",
            "#import <sys/stat.h>",
            "#import <sys/mount.h>",
            "#import <sys/socket.h>",
            "#import <netinet/in.h>",
            "#import <arpa/inet.h>",
            "#import <unistd.h>",
            "#import <dlfcn.h>",
            "#import <mach-o/dyld.h>",
            "#import <mach/mach.h>",
            "#import <Security/Security.h>",
            "#import <signal.h>",
            "#import <substrate.h>",
            "",
            "#define LOG_TAG @\"[" + self.tweak_name + "] \"",
            "#define TLog(fmt, ...) NSLog(LOG_TAG fmt, ##__VA_ARGS__)",
            "",
        ]

        # ----------------------------------------------------------------------
        # 1. 反调试拦截函数 (C 层 Hook)
        # ----------------------------------------------------------------------
        code.append("// ============================================================================")
        code.append("// 1. 反调试防护绕过模块 (Anti-Debug Bypass)")
        code.append("// ============================================================================")
        code.append("")

        if need_ptrace:
            code.append("""// [AD-001] ptrace 反调试拦截
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int request, pid_t pid, caddr_t addr, int data);
static ptrace_ptr_t orig_ptrace = NULL;
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) {
        TLog(@"[Anti-Debug] 成功拦截 ptrace(PT_DENY_ATTACH) 调用");
        return 0;
    }
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}
""")

        if need_sysctl:
            code.append("""// [AD-002] sysctl P_TRACED 调试标志抹除
typedef int (*sysctl_ptr_t)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static sysctl_ptr_t orig_sysctl = NULL;
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (name && namelen >= 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        if (oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            if ((info->kp_proc.p_flag & P_TRACED) != 0) {
                info->kp_proc.p_flag &= ~P_TRACED;
                TLog(@"[Anti-Debug] 清除 sysctl kinfo_proc 中的 P_TRACED 标志位");
            }
        }
    }
    return ret;
}
""")

        if need_getppid:
            code.append("""// [AD-005] getppid 调试器父进程伪装
typedef pid_t (*getppid_ptr_t)(void);
static getppid_ptr_t orig_getppid = NULL;
static pid_t my_getppid(void) {
    // 始终返回 launchd PID (1)
    return 1;
}
""")

        if need_isatty:
            code.append("""// [AD-007] isatty 终端调试探测拦截
typedef int (*isatty_ptr_t)(int fd);
static isatty_ptr_t orig_isatty = NULL;
static int my_isatty(int fd) {
    return 0;
}
""")

        if need_signal:
            code.append("""// [AD-004] signal / sigaction 异常信号拦截
typedef sig_t (*signal_ptr_t)(int sig, sig_t func);
static signal_ptr_t orig_signal = NULL;
static sig_t my_signal(int sig, sig_t func) {
    if (sig == SIGTRAP || sig == SIGBUS || sig == SIGSEGV) {
        TLog(@"[Anti-Debug] 拦截针对调试信号 %d 的注册", sig);
        return SIG_DFL;
    }
    return orig_signal ? orig_signal(sig, func) : SIG_DFL;
}
""")

        if need_task_ports:
            code.append("""// [AD-003] task_set_exception_ports 断点异常端口保护拦截
typedef kern_return_t (*task_set_exception_ports_ptr_t)(
    task_t task,
    exception_mask_t mask,
    mach_port_t new_port,
    exception_behavior_t behavior,
    thread_state_flavor_t new_flavor
);
static task_set_exception_ports_ptr_t orig_task_set_exception_ports = NULL;
static kern_return_t my_task_set_exception_ports(
    task_t task,
    exception_mask_t mask,
    mach_port_t new_port,
    exception_behavior_t behavior,
    thread_state_flavor_t new_flavor
) {
    if (mask & (EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS)) {
        TLog(@"[Anti-Debug] 拦截覆盖宿主断点异常处理端口 (mask: 0x%x)", mask);
        return KERN_SUCCESS;
    }
    return orig_task_set_exception_ports ? orig_task_set_exception_ports(task, mask, new_port, behavior, new_flavor) : KERN_SUCCESS;
}
""")

        # ----------------------------------------------------------------------
        # 2. 越狱检测拦截 (C + OC)
        # ----------------------------------------------------------------------
        code.append("// ============================================================================")
        code.append("// 2. 越狱检测绕过模块 (Jailbreak Detection Bypass)")
        code.append("// ============================================================================")
        code.append("")

        if need_jb_paths:
            code.append("""// [JB-001/JB-006] 常见越狱敏感路径黑名单列表 (Rootful & Rootless)
static BOOL is_jailbreak_path(const char *path) {
    if (!path) return NO;
    static const char *jb_indicators[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Filza.app",
        "/Applications/blackra1n.app",
        "/Library/MobileSubstrate",
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/bin/bash",
        "/bin/sh",
        "/etc/apt",
        "/etc/ssh/sshd_config",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/var/jb/",
        "/var/jb/Applications",
        "/var/jb/usr/bin",
        "/var/jb/usr/lib",
        "/var/jb/Library",
        "/var/jb/basebins",
        "/private/preboot/jb",
        "/jb/usr/lib",
        "/var/binpack",
        "SubstrateLoader.dylib",
        "libjailbreak.dylib",
        "ElleKit.dylib",
        "Substitute.dylib",
        NULL
    };
    for (int i = 0; jb_indicators[i] != NULL; i++) {
        if (strstr(path, jb_indicators[i]) != NULL) {
            return YES;
        }
    }
    return NO;
}

// C 文件 API 拦截
typedef int (*stat_ptr_t)(const char *path, struct stat *buf);
static stat_ptr_t orig_stat = NULL;
static int my_stat(const char *path, struct stat *buf) {
    if (is_jailbreak_path(path)) {
        TLog(@"[Jailbreak] 拦截 stat 越狱探测: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(path, buf) : -1;
}

typedef int (*lstat_ptr_t)(const char *path, struct stat *buf);
static lstat_ptr_t orig_lstat = NULL;
static int my_lstat(const char *path, struct stat *buf) {
    if (is_jailbreak_path(path)) {
        TLog(@"[Jailbreak] 拦截 lstat 越狱探测: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(path, buf) : -1;
}

typedef int (*access_ptr_t)(const char *path, int mode);
static access_ptr_t orig_access = NULL;
static int my_access(const char *path, int mode) {
    if (is_jailbreak_path(path)) {
        TLog(@"[Jailbreak] 拦截 access 越狱探测: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, mode) : -1;
}

typedef FILE *(*fopen_ptr_t)(const char *path, const char *mode);
static fopen_ptr_t orig_fopen = NULL;
static FILE *my_fopen(const char *path, const char *mode) {
    if (is_jailbreak_path(path)) {
        TLog(@"[Jailbreak] 拦截 fopen 越狱探测: %s", path);
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen ? orig_fopen(path, mode) : NULL;
}
""")

        if need_jb_dyld:
            code.append("""// [JB-004] Dyld 动态库镜像遍历检测绕过
typedef const char *(*dyld_get_image_name_ptr_t)(uint32_t image_index);
static dyld_get_image_name_ptr_t orig_dyld_get_image_name = NULL;
static const char *my_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : NULL;
    if (name) {
        if (strstr(name, "MobileSubstrate") || strstr(name, "CydiaSubstrate") ||
            strstr(name, "ElleKit") || strstr(name, "libhooker") ||
            strstr(name, "Substitute") || strstr(name, "FridaGadget") ||
            strstr(name, "frida-agent") || strstr(name, "TweakInject") ||
            strstr(name, "SSLKillSwitch")) {
            return "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"; // 伪装成系统无害库
        }
    }
    return name;
}
""")

        if need_jb_fork:
            code.append("""// [JB-005] 子进程与 Shell 执行检测拦截
typedef int (*system_ptr_t)(const char *command);
static system_ptr_t orig_system = NULL;
static int my_system(const char *command) {
    if (command && (strstr(command, "/bin/") || strstr(command, "cydia") || strstr(command, "dpkg"))) {
        TLog(@"[Jailbreak] 拦截 system 执行探测: %s", command);
        return -1;
    }
    return orig_system ? orig_system(command) : -1;
}

typedef pid_t (*fork_ptr_t)(void);
static fork_ptr_t orig_fork = NULL;
static pid_t my_fork(void) {
    TLog(@"[Jailbreak] 拦截 fork 调用返回 -1 (未越狱沙盒模拟)");
    return -1;
}
""")

        # OC 越狱 Hook 组
        if need_jb_paths or need_jb_sandbox:
            code.append("// Objective-C 越狱检测拦截")
            code.append("%hook NSFileManager")
            if need_jb_paths:
                code.append("""- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && is_jailbreak_path([path UTF8String])) {
        TLog(@"[Jailbreak] 拦截 NSFileManager fileExistsAtPath: %@", path);
        return NO;
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path && is_jailbreak_path([path UTF8String])) {
        TLog(@"[Jailbreak] 拦截 NSFileManager fileExistsAtPath:isDirectory: %@", path);
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    return %orig;
}
""")

            if need_jb_sandbox:
                code.append("""- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    if (path && ([path containsString:@"/private/"] || [path containsString:@"/var/mobile/"])) {
        TLog(@"[Jailbreak] 拦截沙盒逃逸写测试: %@", path);
        return NO;
    }
    return %orig;
}
""")
            code.append("%end // %hook NSFileManager\n")

        if need_jb_scheme:
            code.append("""%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if (url) {
        NSString *scheme = [[url scheme] lowercaseString];
        if ([scheme isEqualToString:@"cydia"] || [scheme isEqualToString:@"sileo"] ||
            [scheme isEqualToString:@"zbra"] || [scheme isEqualToString:@"filza"] ||
            [scheme isEqualToString:@"undecimus"] || [scheme isEqualToString:@"taurine"]) {
            TLog(@"[Jailbreak] 拦截 UIApplication canOpenURL 越狱 Scheme: %@", url);
            return NO;
        }
    }
    return %orig;
}
%end // %hook UIApplication
""")

        if need_jb_suite:
            code.append("""// [JB-007] 第三方越狱检测库 (IOSSecuritySuite 等) 整体 Hook
%hook IOSSecuritySuite
+ (BOOL)amIJailbroken { return NO; }
+ (BOOL)amIRuntimeHooked { return NO; }
+ (BOOL)amIDebugged { return NO; }
+ (BOOL)amIReverseEngineered { return NO; }
+ (BOOL)amIProxied { return NO; }
%end

%hook DTTJailbreakDetection
+ (BOOL)isJailbroken { return NO; }
%end
""")

        # ----------------------------------------------------------------------
        # 3. SSL Pinning 证书固定拦截
        # ----------------------------------------------------------------------
        code.append("// ============================================================================")
        code.append("// 3. HTTPS 证书固定绕过模块 (SSL/TLS Pinning Bypass)")
        code.append("// ============================================================================")
        code.append("")

        if need_ssl_sectrust:
            code.append("""// [SSL-004] Security.framework 证书链校验强制通过
typedef OSStatus (*SecTrustEvaluateWithError_ptr_t)(SecTrustRef trust, CFErrorRef *error);
static SecTrustEvaluateWithError_ptr_t orig_SecTrustEvaluateWithError = NULL;
static OSStatus my_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    TLog(@"[SSL-Pinning] 强制放行 SecTrustEvaluateWithError 证书校验");
    if (error) {
        *error = NULL;
    }
    return true;
}

typedef OSStatus (*SecTrustEvaluate_ptr_t)(SecTrustRef trust, SecTrustResultType *result);
static SecTrustEvaluate_ptr_t orig_SecTrustEvaluate = NULL;
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    TLog(@"[SSL-Pinning] 强制放行 SecTrustEvaluate 证书校验");
    if (result) {
        *result = kSecTrustResultProceed;
    }
    return errSecSuccess;
}
""")

        if need_ssl_afn:
            code.append("""// [SSL-002] AFNetworking / AFSecurityPolicy 证书策略绕过
%hook AFSecurityPolicy
- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust forDomain:(NSString *)domain {
    TLog(@"[SSL-Pinning] 强制通过 AFSecurityPolicy evaluateServerTrust:forDomain: %@", domain);
    return YES;
}
- (void)setSSLPinningMode:(NSUInteger)mode {
    // 0: AFSSLPinningModeNone
    TLog(@"[SSL-Pinning] 重置 AFSecurityPolicy SSLPinningMode 为 None");
    %orig(0);
}
%end
""")

        if need_ssl_trustkit:
            code.append("""// [SSL-001] TrustKit 证书绑定框架绕过
%hook TSKPinningValidator
- (NSUInteger)evaluateTrust:(SecTrustRef)serverTrust forHostname:(NSString *)serverHostname {
    TLog(@"[SSL-Pinning] TrustKit evaluateTrust 强制返回 TSKTrustEvaluationSuccess (0)");
    return 0; // TSKTrustEvaluationSuccess
}
%end
""")

        # ----------------------------------------------------------------------
        # 4. Frida & 动态 Hook 检测拦截
        # ----------------------------------------------------------------------
        code.append("// ============================================================================")
        code.append("// 4. Frida / Hook 动态检测绕过模块 (Frida Detection Bypass)")
        code.append("// ============================================================================")
        code.append("")

        if need_frida_port:
            code.append("""// [FH-001] 拦截 Frida 默认服务端口扫描 (27042, 27043, 23924, 23946 等)
typedef int (*connect_ptr_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static connect_ptr_t orig_connect = NULL;
static int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        uint16_t port = ntohs(in->sin_port);
        if (port == 27042 || port == 27043 || port == 23924 || port == 23946) {
            TLog(@"[Frida-Detect] 拦截向 Frida 特征端口 %d 发起的扫描连接", port);
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
}
""")

        if need_frida_thread:
            code.append("""// [FH-003] 隐藏 Frida 运行时工作线程名
typedef int (*pthread_getname_np_ptr_t)(pthread_t thread, char *name, size_t len);
static pthread_getname_np_ptr_t orig_pthread_getname_np = NULL;
static int my_pthread_getname_np(pthread_t thread, char *name, size_t len) {
    int ret = orig_pthread_getname_np ? orig_pthread_getname_np(thread, name, len) : 0;
    if (ret == 0 && name) {
        if (strstr(name, "gum-js-loop") || strstr(name, "gmain") || strstr(name, "pool-frida")) {
            strncpy(name, "worker_thread", len);
        }
    }
    return ret;
}
""")

        # ----------------------------------------------------------------------
        # 5. %ctor 初始化入口绑定
        # ----------------------------------------------------------------------
        code.append("// ============================================================================")
        code.append("// 5. 构造函数初始化 (Hook Registration)")
        code.append("// ============================================================================")
        code.append("%ctor {")
        code.append("    @autoreleasepool {")
        code.append(f'        TLog(@"=== {self.tweak_name} 插件加载成功，正在注册安全防护 Bypass 逻辑 ===");')


        if need_ptrace:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"ptrace\"), (void *)my_ptrace, (void **)&orig_ptrace);")
        if need_sysctl:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"sysctl\"), (void *)my_sysctl, (void **)&orig_sysctl);")
        if need_getppid:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"getppid\"), (void *)my_getppid, (void **)&orig_getppid);")
        if need_isatty:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"isatty\"), (void *)my_isatty, (void **)&orig_isatty);")
        if need_signal:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"signal\"), (void *)my_signal, (void **)&orig_signal);")
        if need_task_ports:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"task_set_exception_ports\"), (void *)my_task_set_exception_ports, (void **)&orig_task_set_exception_ports);")

        if need_jb_paths:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"stat\"), (void *)my_stat, (void **)&orig_stat);")
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"lstat\"), (void *)my_lstat, (void **)&orig_lstat);")
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"access\"), (void *)my_access, (void **)&orig_access);")
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"fopen\"), (void *)my_fopen, (void **)&orig_fopen);")

        if need_jb_dyld:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"_dyld_get_image_name\"), (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);")
        if need_jb_fork:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"system\"), (void *)my_system, (void **)&orig_system);")
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"fork\"), (void *)my_fork, (void **)&orig_fork);")

        if need_ssl_sectrust:
            code.append("        void *secTrustErr = dlsym(RTLD_DEFAULT, \"SecTrustEvaluateWithError\");")
            code.append("        if (secTrustErr) MSHookFunction(secTrustErr, (void *)my_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError);")
            code.append("        void *secTrust = dlsym(RTLD_DEFAULT, \"SecTrustEvaluate\");")
            code.append("        if (secTrust) MSHookFunction(secTrust, (void *)my_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);")

        if need_frida_port:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"connect\"), (void *)my_connect, (void **)&orig_connect);")
        if need_frida_thread:
            code.append("        MSHookFunction((void *)dlsym(RTLD_DEFAULT, \"pthread_getname_np\"), (void *)my_pthread_getname_np, (void **)&orig_pthread_getname_np);")

        code.append("""
        TLog(@"=== 安全防护 Bypass 规则已全部挂钩生效 ===");
    }
}
""")
        return "\n".join(code)

    def generate_makefile(self, rootless: bool = True) -> str:
        """生成 Theos Makefile"""
        rootless_flag = "THEOS_PACKAGE_SCHEME = rootless" if rootless else "# THEOS_PACKAGE_SCHEME = rootful"
        return f"""# ==============================================================================
# Makefile for {self.tweak_name}
# ==============================================================================

# 自动检测 THEOS 安装路径 (优先读取环境变量，默认回退到 ~/theos 或 /opt/theos)
ifndef THEOS
  THEOS := $(HOME)/theos
  ifeq ($(wildcard $(THEOS)/*),)
    THEOS := /opt/theos
  endif
endif

# 支持 iOS 14.0 - 17.x
TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e

# Rootless / Dopamine / Palera1n 支持配置
{rootless_flag}

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = {self.tweak_name}

{self.tweak_name}_FILES = Tweak.x
{self.tweak_name}_CFLAGS = -fobjc-arc -Wno-unused-variable -Wno-unused-function
{self.tweak_name}_FRAMEWORKS = Foundation UIKit Security
{self.tweak_name}_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
\tinstall.exec "killall -9 {self.pkg.executable_name or 'SpringBoard'}" || true
"""

    def generate_control(self, rootless: bool = True) -> str:
        """生成 Debian 包描述文件 control"""
        dep = "mobilesubstrate (>= 0.9.5000)" if not rootless else "ellekit | mobilesubstrate"
        bundle_id = (self.pkg.bundle_id or "com.target.app").lower()
        return f"""Package: com.{self.author.lower()}.{self.tweak_name.lower()}
Name: {self.tweak_name}
Depends: {dep}
Version: 1.0.0
Architecture: iphoneos-arm
Description: Automated security protection bypass tweak for {self.pkg.display_name or self.pkg.bundle_name}
Maintainer: {self.author}
Author: {self.author}
Section: Tweaks
"""

    def generate_plist(self) -> str:
        """生成进程过滤配置 Plist"""
        target_bundle = self.pkg.bundle_id or "com.target.app"
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Filter</key>
    <dict>
        <key>Bundles</key>
        <array>
            <string>{target_bundle}</string>
        </array>
    </dict>
</dict>
</plist>
"""

    def generate_frida_bypass(self, force_all: bool = False) -> str:
        """生成双模 Frida 动态 Bypass 脚本 (bypass.js)"""
        hits = self.hit_rule_ids
        need_ptrace = force_all or "AD-001" in hits
        need_sysctl = force_all or "AD-002" in hits
        need_getppid = force_all or "AD-005" in hits
        need_jb_paths = force_all or "JB-001" in hits or "JB-006" in hits
        need_jb_scheme = force_all or "JB-002" in hits
        need_ssl = force_all or "SSL-001" in hits or "SSL-002" in hits or "SSL-004" in hits
        need_frida_port = force_all or "FH-001" in hits

        js = [
            "/*",
            f" * Frida Dynamic Bypass Script for {self.pkg.bundle_id or 'Target'}",
            f" * Generated automatically by analyze.py / TweakGenerator",
            " * Usage: frida -U -f " + (self.pkg.bundle_id or "<BundleId>") + " -l bypass.js",
            " */",
            "",
            "(function() {",
            "    console.log('[*] [Frida] === 正在注入自动化安全防护 Bypass 脚本 ===');",
            "",
        ]

        if need_ptrace:
            js.append("""    // 1. [AD-001] ptrace PT_DENY_ATTACH 拦截
    const ptracePtr = Module.findExportByName(null, 'ptrace');
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function(args) {
                const request = args[0].toInt32();
                if (request === 31) { // PT_DENY_ATTACH
                    console.log('[+] [Anti-Debug] 拦截 ptrace(PT_DENY_ATTACH)');
                    this.blocked = true;
                }
            },
            onLeave: function(retval) {
                if (this.blocked) {
                    retval.replace(0);
                }
            }
        });
    }
""")

        if need_sysctl:
            js.append("""    // 2. [AD-002] sysctl P_TRACED 标志位清除
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
""")

        if need_getppid:
            js.append("""    // 3. [AD-005] getppid 伪装
    const getppidPtr = Module.findExportByName(null, 'getppid');
    if (getppidPtr) {
        Interceptor.attach(getppidPtr, {
            onLeave: function(retval) {
                retval.replace(1);
            }
        });
    }
""")

        if need_jb_paths:
            js.append("""    // 4. [JB-001] 越狱文件与路径探测拦截 (stat / lstat / access / open)
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
""")

        if need_jb_scheme:
            js.append("""    // 5. [JB-002] canOpenURL 越狱 Scheme 拦截
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
""")

        if need_ssl:
            js.append("""    // 6. [SSL-004] SecTrust 证书链校验绕过
    const secTrustErrPtr = Module.findExportByName(null, 'SecTrustEvaluateWithError');
    if (secTrustErrPtr) {
        Interceptor.attach(secTrustErrPtr, {
            onLeave: function(retval) {
                console.log('[+] [SSL-Pinning] 放行 SecTrustEvaluateWithError');
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
""")

        if need_frida_port:
            js.append("""    // 7. [FH-001] Frida 默认端口扫描拦截 (27042, 27043, 23924, 23946)
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
""")

        js.append("    console.log('[*] [Frida] === Bypass 脚本挂钩全部就绪 ===');")
        js.append("})();\n")
        return "\n".join(js)

    def generate_readme(self) -> str:
        """生成 Tweak 工程使用说明"""
        return f"""# {self.tweak_name}

自动化生成的 iOS 安全防护 Bypass 插件与动态调试脚本。

- **目标应用**: `{self.pkg.display_name or self.pkg.bundle_name}`
- **Bundle ID**: `{self.pkg.bundle_id}`
- **可执行文件**: `{self.pkg.executable_name}`

---

## 🛠 方法一：使用 Theos 编译并安装到越狱设备

### 1. 环境准备
确保已安装 Theos (https://theos.dev/)。

### 2. 编译插件
```bash
# 进入当前插件目录
cd {self.tweak_name}

# 编译 deb 包 (支持 iOS 14 - 17 Rootless 与 Rootful)
make package FINALPACKAGE=1

# 或一键编译并安装到手机 (需配置 THEOS_DEVICE_IP=127.0.0.1 THEOS_DEVICE_PORT=2222)
make do
```

---

## ⚡ 方法二：使用 Frida 动态免编译即时加载

若不希望安装 Theos 编译环境，可直接使用附带的 `bypass.js` 进行动态拦截：

```bash
# 启动并挂钩目标 App
frida -U -f {self.pkg.bundle_id or self.pkg.executable_name} -l bypass.js

# 或附加到已运行的 App
frida -U -n "{self.pkg.executable_name}" -l bypass.js
```
"""
