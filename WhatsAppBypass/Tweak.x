// ============================================================================
// WhatsAppBypass - 自动化生成的安全防护 Bypass 插件
// 目标应用: ‎WA Business (net.whatsapp.WhatsAppSMB)
// 生成时间: Tue Aug 25 14:12:15 CST 2026
// 基于 analyze.py 静态扫描分析结果精准定制生成
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <Security/Security.h>
#import <signal.h>
#import <substrate.h>

#define LOG_TAG @"[WhatsAppBypass] "
#define TLog(fmt, ...) NSLog(LOG_TAG fmt, ##__VA_ARGS__)

// ============================================================================
// 1. 反调试防护绕过模块 (Anti-Debug Bypass)
// ============================================================================

// [AD-002] sysctl P_TRACED 调试标志抹除
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

// [AD-007] isatty 终端调试探测拦截
typedef int (*isatty_ptr_t)(int fd);
static isatty_ptr_t orig_isatty = NULL;
static int my_isatty(int fd) {
    return 0;
}

// [AD-004] signal / sigaction 异常信号拦截
typedef sig_t (*signal_ptr_t)(int sig, sig_t func);
static signal_ptr_t orig_signal = NULL;
static sig_t my_signal(int sig, sig_t func) {
    if (sig == SIGTRAP || sig == SIGBUS || sig == SIGSEGV) {
        TLog(@"[Anti-Debug] 拦截针对调试信号 %d 的注册", sig);
        return SIG_DFL;
    }
    return orig_signal ? orig_signal(sig, func) : SIG_DFL;
}

// [AD-003] task_set_exception_ports 断点异常端口保护拦截
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

// ============================================================================
// 2. 越狱检测绕过模块 (Jailbreak Detection Bypass)
// ============================================================================

// [JB-001/JB-006] 常见越狱敏感路径黑名单列表 (Rootful & Rootless)
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

// [JB-004] Dyld 动态库镜像遍历检测绕过
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

// [JB-005] 子进程与 Shell 执行检测拦截
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

// Objective-C 越狱检测拦截
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
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

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    if (path && ([path containsString:@"/private/"] || [path containsString:@"/var/mobile/"])) {
        TLog(@"[Jailbreak] 拦截沙盒逃逸写测试: %@", path);
        return NO;
    }
    return %orig;
}

%end // %hook NSFileManager

%hook UIApplication
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

// [JB-007] 第三方越狱检测库 (IOSSecuritySuite 等) 整体 Hook
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

// ============================================================================
// 3. HTTPS 证书固定绕过模块 (SSL/TLS Pinning Bypass)
// ============================================================================

// [SSL-004] Security.framework 证书链校验强制通过
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

// ============================================================================
// 4. Frida / Hook 动态检测绕过模块 (Frida Detection Bypass)
// ============================================================================

// [FH-001] 拦截 Frida 默认服务端口扫描 (27042, 27043, 23924, 23946 等)
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

// ============================================================================
// 5. 构造函数初始化 (Hook Registration)
// ============================================================================
%ctor {
    @autoreleasepool {
        TLog(@"=== WhatsAppBypass 插件加载成功，正在注册安全防护 Bypass 逻辑 ===");
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "sysctl"), (void *)my_sysctl, (void **)&orig_sysctl);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "isatty"), (void *)my_isatty, (void **)&orig_isatty);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "signal"), (void *)my_signal, (void **)&orig_signal);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "task_set_exception_ports"), (void *)my_task_set_exception_ports, (void **)&orig_task_set_exception_ports);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "stat"), (void *)my_stat, (void **)&orig_stat);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "lstat"), (void *)my_lstat, (void **)&orig_lstat);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "access"), (void *)my_access, (void **)&orig_access);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "fopen"), (void *)my_fopen, (void **)&orig_fopen);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "_dyld_get_image_name"), (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "system"), (void *)my_system, (void **)&orig_system);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "fork"), (void *)my_fork, (void **)&orig_fork);
        void *secTrustErr = dlsym(RTLD_DEFAULT, "SecTrustEvaluateWithError");
        if (secTrustErr) MSHookFunction(secTrustErr, (void *)my_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError);
        void *secTrust = dlsym(RTLD_DEFAULT, "SecTrustEvaluate");
        if (secTrust) MSHookFunction(secTrust, (void *)my_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "connect"), (void *)my_connect, (void **)&orig_connect);

        TLog(@"=== 安全防护 Bypass 规则已全部挂钩生效 ===");
    }
}
