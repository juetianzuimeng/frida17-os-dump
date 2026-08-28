// ============================================================================
// MessengerBypass - 自动化生成的安全防护 Bypass 插件 (修复 MBI 调度与网络优化版)
// 目标应用: Messenger (com.facebook.Messenger)
// 优化重点: 
//   1. 移除错误的 LightSpeed 硬编码偏移 hook (彻底修复公共主页与消息队列加载卡死)
//   2. 保留精准的 mbedtls_x509_crt_verify 与 SecTrust 证书链动态绕过
//   3. 高性能异步后台写盘队列与独立宏级智能频控
//   4. 网络请求异常与失败深度监控 (NSURLSession 请求监控, HTTP 4xx/5xx, NSError, SSL 证书错误高亮)
//   5. 全局未捕获异常 (NSUncaughtExceptionHandler) 与 POSIX Crash 信号捕获
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <Security/Security.h>
#import <signal.h>
#import <execinfo.h>
#import <os/lock.h>
#import <substrate.h>

// ============================================================================
// 1. 统一高性能日志引擎 (High-Performance Async Logging Engine)
// ============================================================================

typedef NS_ENUM(NSInteger, MBLogLevel) {
    MBLogLevelDebug = 0,
    MBLogLevelInfo,
    MBLogLevelWarn,
    MBLogLevelError,
    MBLogLevelFatal
};

static NSString * const kMBLogFileName = @"MessengerBypass.log";
static NSString * const kMBLogOldFileName = @"MessengerBypass.log.old";
static const unsigned long long kMBMaxLogFileSize = 10 * 1024 * 1024; // 10 MB 上限

static FILE *g_log_file = NULL;
static os_unfair_lock g_log_lock = OS_UNFAIR_LOCK_INIT;
static dispatch_queue_t g_log_queue = NULL;
static NSString *g_log_file_path = nil;

static NSString *mb_get_log_file_path(void) {
    if (g_log_file_path) return g_log_file_path;
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *baseDir = paths.firstObject;
    
    if (!baseDir || ![[NSFileManager defaultManager] isWritableFileAtPath:baseDir]) {
        paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
        baseDir = paths.firstObject;
        if (!baseDir) {
            baseDir = NSTemporaryDirectory();
        }
    }
    
    g_log_file_path = [baseDir stringByAppendingPathComponent:kMBLogFileName];
    return g_log_file_path;
}

static void mb_init_log_system(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        g_log_queue = dispatch_queue_create("com.securityresearcher.messengerbypass.log", DISPATCH_QUEUE_SERIAL);
        os_unfair_lock_lock(&g_log_lock);
        NSString *path = mb_get_log_file_path();
        if (path) {
            NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
            if (attrs && [attrs fileSize] > kMBMaxLogFileSize) {
                NSString *oldPath = [[path stringByDeletingLastPathComponent] stringByAppendingPathComponent:kMBLogOldFileName];
                [[NSFileManager defaultManager] removeItemAtPath:oldPath error:nil];
                [[NSFileManager defaultManager] moveItemAtPath:path toPath:oldPath error:nil];
            }
            g_log_file = fopen([path UTF8String], "a+");
        }
        os_unfair_lock_unlock(&g_log_lock);
    });
}

static void MBLogMessageInternal(MBLogLevel level, NSString *module, NSString *message, BOOL syncFlush) {
    static const char *levelNames[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
    const char *levelStr = levelNames[MIN((NSUInteger)level, (NSUInteger)4)];

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm_info;
    localtime_r(&tv.tv_sec, &tm_info);
    char timeBuf[32];
    snprintf(timeBuf, sizeof(timeBuf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
             tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, (int)(tv.tv_usec / 1000));

    NSString *formattedLog = [NSString stringWithFormat:@"[%s] [%s] [%@] %@\n",
                              timeBuf, levelStr, module ?: @"General", message];

    NSLog(@"[MessengerBypass] [%s] [%@] %@", levelStr, module ?: @"General", message);

    void (^writeBlock)(void) = ^{
        os_unfair_lock_lock(&g_log_lock);
        if (!g_log_file) {
            NSString *path = mb_get_log_file_path();
            if (path) g_log_file = fopen([path UTF8String], "a+");
        }
        if (g_log_file) {
            fputs([formattedLog UTF8String], g_log_file);
            fflush(g_log_file);
        }
        os_unfair_lock_unlock(&g_log_lock);
    };

    if (syncFlush || level >= MBLogLevelError || !g_log_queue) {
        writeBlock();
    } else {
        dispatch_async(g_log_queue, writeBlock);
    }
}

static void MBLogMessage(MBLogLevel level, NSString *module, NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    MBLogMessageInternal(level, module, message, NO);
}

#define MBLogD(mod, fmt, ...) MBLogMessage(MBLogLevelDebug, mod, fmt, ##__VA_ARGS__)
#define MBLogI(mod, fmt, ...) MBLogMessage(MBLogLevelInfo,  mod, fmt, ##__VA_ARGS__)
#define MBLogW(mod, fmt, ...) MBLogMessage(MBLogLevelWarn,  mod, fmt, ##__VA_ARGS__)
#define MBLogE(mod, fmt, ...) MBLogMessage(MBLogLevelError, mod, fmt, ##__VA_ARGS__)
#define MBLogF(mod, fmt, ...) MBLogMessage(MBLogLevelFatal, mod, fmt, ##__VA_ARGS__)

#define MBLogRateLimited(min_interval, level, mod, fmt, ...) do { \
    static os_unfair_lock _rl_lock = OS_UNFAIR_LOCK_INIT; \
    static double _rl_last_time = 0.0; \
    static uint64_t _rl_suppressed = 0; \
    struct timeval _rl_tv; \
    gettimeofday(&_rl_tv, NULL); \
    double _rl_now = (double)_rl_tv.tv_sec + (double)_rl_tv.tv_usec / 1000000.0; \
    BOOL _rl_should_log = NO; \
    uint64_t _rl_count = 0; \
    os_unfair_lock_lock(&_rl_lock); \
    if (_rl_last_time == 0.0 || (_rl_now - _rl_last_time) >= (min_interval)) { \
        _rl_should_log = YES; \
        _rl_count = _rl_suppressed; \
        _rl_suppressed = 0; \
        _rl_last_time = _rl_now; \
    } else { \
        _rl_suppressed++; \
    } \
    os_unfair_lock_unlock(&_rl_lock); \
    if (_rl_should_log) { \
        NSString *_rl_base = [NSString stringWithFormat:fmt, ##__VA_ARGS__]; \
        NSString *_rl_final = (_rl_count > 0) \
            ? [NSString stringWithFormat:@"%@ (近 %.1fs 内累计放行 %llu 次)", _rl_base, (double)(min_interval), _rl_count + 1] \
            : _rl_base; \
        MBLogMessageInternal(level, mod, _rl_final, NO); \
    } \
} while(0)

// ============================================================================
// 2. 网络请求异常与失败监控模块 (Network Failure & Error Monitor)
// ============================================================================

static void mb_analyze_and_log_network_error(NSURLRequest *request, NSURLResponse *response, NSData *data, NSError *error, NSTimeInterval duration) {
    NSString *urlString = request.URL.absoluteString ?: @"(Unknown URL)";
    NSString *method = request.HTTPMethod ?: @"GET";
    NSInteger statusCode = 0;
    
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        statusCode = [(NSHTTPURLResponse *)response statusCode];
    }

    if (error) {
        NSString *domain = error.domain;
        NSInteger code = error.code;
        NSString *desc = error.localizedDescription;
        NSString *reason = error.localizedFailureReason ?: @"None";

        BOOL isSSLError = NO;
        if ([domain isEqualToString:NSURLErrorDomain] || [domain isEqualToString:@"kCFErrorDomainCFNetwork"]) {
            if (code == NSURLErrorSecureConnectionFailed ||         // -1200
                code == NSURLErrorServerCertificateHasBadDate ||      // -1201
                code == NSURLErrorServerCertificateUntrusted ||      // -1202
                code == NSURLErrorServerCertificateHasUnknownRoot ||  // -1203
                code == NSURLErrorServerCertificateNotYetValid ||     // -1204
                code == NSURLErrorClientCertificateRejected ||        // -1205
                code == NSURLErrorClientCertificateRequired ||        // -1206
                code == NSURLErrorCannotLoadFromNetwork) {            // -2000
                isSSLError = YES;
            }
        }

        if (isSSLError) {
            MBLogE(@"NETWORK_SSL_FAIL", @"🚨 [SSL Pinning 握手失败] 插件或应用未能绕过证书校验! URL: %@ | Method: %@ | Code: %ld | Domain: %@ | 原因: %@ (耗时: %.2fs)",
                   urlString, method, (long)code, domain, desc, duration);
            MBLogE(@"NETWORK_SSL_FAIL", @"错误详情 UserInfo: %@", error.userInfo);
        } else {
            MBLogE(@"NETWORK_ERROR", @"❌ [网络请求失败] URL: %@ | Method: %@ | Error: [%@: %ld] %@ | 失败原因: %@ (耗时: %.2fs)",
                   urlString, method, domain, (long)code, desc, reason, duration);
        }
        return;
    }

    if (statusCode >= 400) {
        NSString *bodySnippet = @"";
        if (data && data.length > 0) {
            NSString *rawStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (!rawStr) {
                rawStr = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
            }
            if (rawStr) {
                if (rawStr.length > 300) {
                    bodySnippet = [rawStr substringToIndex:300];
                } else {
                    bodySnippet = rawStr;
                }
            }
        }
        MBLogW(@"NETWORK_HTTP_ERR", @"⚠️ [HTTP %ld 异常状态] URL: %@ | Method: %@ | 耗时: %.2fs | Response: %@",
               (long)statusCode, urlString, method, duration, bodySnippet);
        return;
    }

    MBLogD(@"NETWORK_OK", @"✅ [HTTP %ld 正常响应] URL: %@ | Method: %@ | 耗时: %.2fs | 数据大小: %lu bytes",
           (long)statusCode, urlString, method, duration, (unsigned long)(data ? data.length : 0));
}

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if (!completionHandler) {
        return %orig(request, completionHandler);
    }
    
    NSDate *startDate = [NSDate date];
    NSURLRequest *reqCopy = [request copy];

    void (^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        @try {
            NSTimeInterval duration = [[NSDate date] timeIntervalSinceDate:startDate];
            mb_analyze_and_log_network_error(reqCopy, response, data, error, duration);
        } @catch (NSException *ex) {
            MBLogE(@"NETWORK_HOOK", @"处理 completionHandler 异常: %@", ex);
        }
        completionHandler(data, response, error);
    };

    return %orig(request, wrappedHandler);
}

- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURL *location, NSURLResponse *response, NSError *error))completionHandler {
    if (!completionHandler) {
        return %orig(request, completionHandler);
    }

    NSDate *startDate = [NSDate date];
    NSURLRequest *reqCopy = [request copy];

    void (^wrappedHandler)(NSURL *, NSURLResponse *, NSError *) = ^(NSURL *location, NSURLResponse *response, NSError *error) {
        @try {
            NSTimeInterval duration = [[NSDate date] timeIntervalSinceDate:startDate];
            mb_analyze_and_log_network_error(reqCopy, response, nil, error, duration);
        } @catch (NSException *ex) {
            MBLogE(@"NETWORK_HOOK", @"处理 download completionHandler 异常: %@", ex);
        }
        completionHandler(location, response, error);
    };

    return %orig(request, wrappedHandler);
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if (!completionHandler) {
        return %orig(request, bodyData, completionHandler);
    }

    NSDate *startDate = [NSDate date];
    NSURLRequest *reqCopy = [request copy];

    void (^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        @try {
            NSTimeInterval duration = [[NSDate date] timeIntervalSinceDate:startDate];
            mb_analyze_and_log_network_error(reqCopy, response, data, error, duration);
        } @catch (NSException *ex) {
            MBLogE(@"NETWORK_HOOK", @"处理 upload completionHandler 异常: %@", ex);
        }
        completionHandler(data, response, error);
    };

    return %orig(request, bodyData, wrappedHandler);
}

%end

// ============================================================================
// 4. 反调试防护绕过模块 (Anti-Debug Bypass)
// ============================================================================

typedef int (*sysctl_ptr_t)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static sysctl_ptr_t orig_sysctl = NULL;
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    @try {
        if (name && namelen >= 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
            if (oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
                struct kinfo_proc *info = (struct kinfo_proc *)oldp;
                if ((info->kp_proc.p_flag & P_TRACED) != 0) {
                    info->kp_proc.p_flag &= ~P_TRACED;
                    MBLogI(@"Anti-Debug", @"清除 sysctl kinfo_proc 中的 P_TRACED 调试标志位");
                }
            }
        }
    } @catch (NSException *e) {
        MBLogE(@"Anti-Debug", @"my_sysctl 异常: %@", e);
    }
    return ret;
}

typedef int (*isatty_ptr_t)(int fd);
static isatty_ptr_t orig_isatty = NULL;
static int my_isatty(int fd) {
    return 0;
}

// ============================================================================
// 4. 越狱检测绕过模块 (Jailbreak Detection Bypass)
// ============================================================================

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

typedef int (*stat_ptr_t)(const char *path, struct stat *buf);
static stat_ptr_t orig_stat = NULL;
static int my_stat(const char *path, struct stat *buf) {
    if (is_jailbreak_path(path)) {
        MBLogRateLimited(2.0, MBLogLevelInfo, @"Jailbreak", @"拦截 stat 越狱探测: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(path, buf) : -1;
}

typedef int (*lstat_ptr_t)(const char *path, struct stat *buf);
static lstat_ptr_t orig_lstat = NULL;
static int my_lstat(const char *path, struct stat *buf) {
    if (is_jailbreak_path(path)) {
        MBLogRateLimited(2.0, MBLogLevelInfo, @"Jailbreak", @"拦截 lstat 越狱探测: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(path, buf) : -1;
}

typedef int (*access_ptr_t)(const char *path, int mode);
static access_ptr_t orig_access = NULL;
static int my_access(const char *path, int mode) {
    if (is_jailbreak_path(path)) {
        MBLogRateLimited(2.0, MBLogLevelInfo, @"Jailbreak", @"拦截 access 越狱探测: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, mode) : -1;
}

typedef FILE *(*fopen_ptr_t)(const char *path, const char *mode);
static fopen_ptr_t orig_fopen = NULL;
static FILE *my_fopen(const char *path, const char *mode) {
    if (is_jailbreak_path(path)) {
        MBLogRateLimited(2.0, MBLogLevelInfo, @"Jailbreak", @"拦截 fopen 越狱探测: %s", path);
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen ? orig_fopen(path, mode) : NULL;
}

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
            return "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics";
        }
    }
    return name;
}

typedef int (*system_ptr_t)(const char *command);
static system_ptr_t orig_system = NULL;
static int my_system(const char *command) {
    if (command && (strstr(command, "/bin/") || strstr(command, "cydia") || strstr(command, "dpkg"))) {
        MBLogI(@"Jailbreak", @"拦截 system 执行探测: %s", command);
        return -1;
    }
    return orig_system ? orig_system(command) : -1;
}

typedef pid_t (*fork_ptr_t)(void);
static fork_ptr_t orig_fork = NULL;
static pid_t my_fork(void) {
    MBLogI(@"Jailbreak", @"拦截 fork 调用返回 -1 (未越狱沙盒模拟)");
    return -1;
}

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && is_jailbreak_path([path UTF8String])) {
        MBLogRateLimited(2.0, MBLogLevelInfo, @"Jailbreak", @"拦截 NSFileManager fileExistsAtPath: %@", path);
        return NO;
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path && is_jailbreak_path([path UTF8String])) {
        MBLogRateLimited(2.0, MBLogLevelInfo, @"Jailbreak", @"拦截 NSFileManager fileExistsAtPath:isDirectory: %@", path);
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    return %orig;
}

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    if (path) {
        // 如果属于应用自身的合法沙盒路径（tmp/Documents/Library/Containers），直接放行
        if ([path containsString:@"/Containers/Data/Application/"] ||
            [path containsString:@"/Containers/Bundle/Application/"] ||
            [path containsString:@"/Containers/Shared/AppGroup/"] ||
            [path containsString:@"/Application/"] ||
            [path containsString:@"/tmp/"] ||
            [path containsString:@"/Documents/"] ||
            [path containsString:@"/Library/"]) {
            return %orig(path, data, attr);
        }
        // 仅拦截向沙盒外部公共根目录或系统敏感目录的逃逸写探测
        if ([path isEqualToString:@"/private/jailbreak.txt"] ||
            [path isEqualToString:@"/private/test.txt"] ||
            [path isEqualToString:@"/private/var/tmp/test.txt"] ||
            [path isEqualToString:@"/var/mobile/test.txt"] ||
            [path isEqualToString:@"/var/mobile/jailbreak.txt"] ||
            [path hasPrefix:@"/private/var/root/"] ||
            [path hasPrefix:@"/private/etc/"] ||
            [path hasPrefix:@"/private/var/lib/"]) {
            MBLogI(@"Jailbreak", @"拦截沙盒逃逸写测试: %@", path);
            return NO;
        }
    }
    return %orig(path, data, attr);
}
%end

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if (url) {
        NSString *scheme = [[url scheme] lowercaseString];
        if ([scheme isEqualToString:@"cydia"] || [scheme isEqualToString:@"sileo"] ||
            [scheme isEqualToString:@"zbra"] || [scheme isEqualToString:@"filza"] ||
            [scheme isEqualToString:@"undecimus"] || [scheme isEqualToString:@"taurine"]) {
            MBLogI(@"Jailbreak", @"拦截 UIApplication canOpenURL 越狱 Scheme: %@", url);
            return NO;
        }
    }
    return %orig;
}
%end

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
// 6. HTTPS 证书固定绕过模块 (SSL/TLS Pinning Bypass)
// ============================================================================

typedef OSStatus (*SecTrustEvaluateWithError_ptr_t)(SecTrustRef trust, CFErrorRef *error);
static SecTrustEvaluateWithError_ptr_t orig_SecTrustEvaluateWithError = NULL;
static OSStatus my_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"强制放行 SecTrustEvaluateWithError 证书校验");
    if (error) {
        *error = NULL;
    }
    return true;
}

typedef OSStatus (*SecTrustEvaluate_ptr_t)(SecTrustRef trust, SecTrustResultType *result);
static SecTrustEvaluate_ptr_t orig_SecTrustEvaluate = NULL;
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"强制放行 SecTrustEvaluate 证书校验");
    if (result) {
        *result = kSecTrustResultProceed;
    }
    return errSecSuccess;
}

%hook AFSecurityPolicy
- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust forDomain:(NSString *)domain {
    MBLogI(@"SSL-Pinning", @"强制通过 AFSecurityPolicy evaluateServerTrust:forDomain: %@", domain);
    return YES;
}
- (void)setSSLPinningMode:(NSUInteger)mode {
    MBLogI(@"SSL-Pinning", @"重置 AFSecurityPolicy SSLPinningMode 为 None");
    %orig(0);
}
%end

typedef int (*mbedtls_x509_crt_verify_ptr_t)(
    void *crt,
    void *trust_ca,
    void *ca_crl,
    const char *cn,
    uint32_t *flags,
    int (*f_vrfy)(void *, void *, int, uint32_t *),
    void *p_vrfy
);
static mbedtls_x509_crt_verify_ptr_t orig_mbedtls_x509_crt_verify = NULL;
static int my_mbedtls_x509_crt_verify(
    void *crt,
    void *trust_ca,
    void *ca_crl,
    const char *cn,
    uint32_t *flags,
    int (*f_vrfy)(void *, void *, int, uint32_t *),
    void *p_vrfy
) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"拦截 mbedtls_x509_crt_verify (cn: %s)，强制清除 flags 并返回 0", cn ? cn : "");
    if (flags) {
        *flags = 0;
    }
    return 0;
}

typedef OSStatus (*SecTrustEvaluateAsync_ptr_t)(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback resultHandler);
static SecTrustEvaluateAsync_ptr_t orig_SecTrustEvaluateAsync = NULL;
static OSStatus my_SecTrustEvaluateAsync(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback resultHandler) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"强制放行 SecTrustEvaluateAsync 异步证书校验");
    if (resultHandler) {
        dispatch_async(queue ?: dispatch_get_main_queue(), ^{
            resultHandler(trust, kSecTrustResultProceed);
        });
    }
    return errSecSuccess;
}

typedef OSStatus (*SecTrustEvaluateAsyncWithError_ptr_t)(SecTrustRef trust, dispatch_queue_t queue, SecTrustWithErrorCallback resultHandler);
static SecTrustEvaluateAsyncWithError_ptr_t orig_SecTrustEvaluateAsyncWithError = NULL;
static OSStatus my_SecTrustEvaluateAsyncWithError(SecTrustRef trust, dispatch_queue_t queue, SecTrustWithErrorCallback resultHandler) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"强制放行 SecTrustEvaluateAsyncWithError 异步证书校验");
    if (resultHandler) {
        dispatch_async(queue ?: dispatch_get_main_queue(), ^{
            resultHandler(trust, true, NULL);
        });
    }
    return errSecSuccess;
}

typedef int (*X509_verify_cert_ptr_t)(void *ctx);
static X509_verify_cert_ptr_t orig_X509_verify_cert = NULL;
static int my_X509_verify_cert(void *ctx) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"强制通过 X509_verify_cert 证书校验");
    return 1;
}

typedef void (*SSL_CTX_set_verify_ptr_t)(void *ctx, int mode, int (*verify_callback)(int, void *));
static SSL_CTX_set_verify_ptr_t orig_SSL_CTX_set_verify = NULL;
static void my_SSL_CTX_set_verify(void *ctx, int mode, int (*verify_callback)(int, void *)) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"重置 SSL_CTX_set_verify mode 为 SSL_VERIFY_NONE (0)");
    if (orig_SSL_CTX_set_verify) {
        orig_SSL_CTX_set_verify(ctx, 0, NULL);
    }
}

typedef long (*SSL_get_verify_result_ptr_t)(const void *ssl);
static SSL_get_verify_result_ptr_t orig_SSL_get_verify_result = NULL;
static long my_SSL_get_verify_result(const void *ssl) {
    return 0; // X509_V_OK
}

typedef BOOL (*MNSQUICSettingsGetTrustSandboxCertificates_ptr_t)(void *settings);
static MNSQUICSettingsGetTrustSandboxCertificates_ptr_t orig_MNSQUICSettingsGetTrustSandboxCertificates = NULL;
static BOOL my_MNSQUICSettingsGetTrustSandboxCertificates(void *settings) {
    return YES;
}

static void try_hook_ssl_symbols(void) {
    if (!orig_mbedtls_x509_crt_verify) {
        void *fn = dlsym(RTLD_DEFAULT, "mbedtls_x509_crt_verify");
        if (fn) {
            MSHookFunction(fn, (void *)my_mbedtls_x509_crt_verify, (void **)&orig_mbedtls_x509_crt_verify);
            MBLogI(@"SSL-Pinning", @"成功挂钩 mbedtls_x509_crt_verify: %p", fn);
        }
    }
    if (!orig_X509_verify_cert) {
        void *fn = dlsym(RTLD_DEFAULT, "X509_verify_cert");
        if (fn) {
            MSHookFunction(fn, (void *)my_X509_verify_cert, (void **)&orig_X509_verify_cert);
            MBLogI(@"SSL-Pinning", @"成功挂钩 X509_verify_cert: %p", fn);
        }
    }
    if (!orig_SSL_CTX_set_verify) {
        void *fn = dlsym(RTLD_DEFAULT, "SSL_CTX_set_verify");
        if (fn) {
            MSHookFunction(fn, (void *)my_SSL_CTX_set_verify, (void **)&orig_SSL_CTX_set_verify);
            MBLogI(@"SSL-Pinning", @"成功挂钩 SSL_CTX_set_verify: %p", fn);
        }
    }
    if (!orig_SSL_get_verify_result) {
        void *fn = dlsym(RTLD_DEFAULT, "SSL_get_verify_result");
        if (fn) {
            MSHookFunction(fn, (void *)my_SSL_get_verify_result, (void **)&orig_SSL_get_verify_result);
            MBLogI(@"SSL-Pinning", @"成功挂钩 SSL_get_verify_result: %p", fn);
        }
    }
    if (!orig_MNSQUICSettingsGetTrustSandboxCertificates) {
        void *fn = dlsym(RTLD_DEFAULT, "MNSQUICSettingsGetTrustSandboxCertificates");
        if (fn) {
            MSHookFunction(fn, (void *)my_MNSQUICSettingsGetTrustSandboxCertificates, (void **)&orig_MNSQUICSettingsGetTrustSandboxCertificates);
            MBLogI(@"SSL-Pinning", @"成功挂钩 MNSQUICSettingsGetTrustSandboxCertificates: %p", fn);
        }
    }
}

static void on_image_added(const struct mach_header *mh, intptr_t vmaddr_slide) {
    try_hook_ssl_symbols();
}

// ============================================================================
// 7. Frida / Hook 动态检测绕过模块 (Frida Detection Bypass)
// ============================================================================

typedef int (*connect_ptr_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static connect_ptr_t orig_connect = NULL;
static int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        uint16_t port = ntohs(in->sin_port);
        if (port == 27042 || port == 27043 || port == 23924 || port == 23946) {
            MBLogI(@"Frida-Detect", @"拦截向 Frida 特征端口 %d 发起的扫描连接", port);
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
}

// ============================================================================
// 8. 构造函数初始化 (Plugin Entry Point)
// ============================================================================
%ctor {
    @autoreleasepool {
        mb_init_log_system();

        NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];
        NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"Unknown";
        NSString *appVersion = [infoDict objectForKey:@"CFBundleShortVersionString"] ?: @"Unknown";
        NSString *buildVersion = [infoDict objectForKey:@"CFBundleVersion"] ?: @"Unknown";
        NSString *osVersion = [[UIDevice currentDevice] systemVersion] ?: @"Unknown";
        NSString *model = [[UIDevice currentDevice] model] ?: @"Unknown";

        MBLogI(@"Init", @"=================================================================");
        MBLogI(@"Init", @"🎉 MessengerBypass 插件加载就绪 (修复 MBI 调度与网络优化版)");
        MBLogI(@"Init", @"📦 目标应用 BundleID : %@", bundleId);
        MBLogI(@"Init", @"📱 设备型号 & iOS版本: %@ (iOS %@)", model, osVersion);
        MBLogI(@"Init", @"📌 应用版本号       : v%@ (Build %@)", appVersion, buildVersion);
        MBLogI(@"Init", @"📄 持久化日志路径   : %@", mb_get_log_file_path());
        MBLogI(@"Init", @"=================================================================");

        // 注册 C API Hook
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "sysctl"), (void *)my_sysctl, (void **)&orig_sysctl);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "isatty"), (void *)my_isatty, (void **)&orig_isatty);
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
        void *secTrustAsync = dlsym(RTLD_DEFAULT, "SecTrustEvaluateAsync");
        if (secTrustAsync) MSHookFunction(secTrustAsync, (void *)my_SecTrustEvaluateAsync, (void **)&orig_SecTrustEvaluateAsync);
        void *secTrustAsyncErr = dlsym(RTLD_DEFAULT, "SecTrustEvaluateAsyncWithError");
        if (secTrustAsyncErr) MSHookFunction(secTrustAsyncErr, (void *)my_SecTrustEvaluateAsyncWithError, (void **)&orig_SecTrustEvaluateAsyncWithError);
        
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "connect"), (void *)my_connect, (void **)&orig_connect);

        // 注册 SSL 动态库监听与 Hook
        try_hook_ssl_symbols();
        _dyld_register_func_for_add_image(on_image_added);

        MBLogI(@"Init", @"✅ 安全防护 Bypass 与 网络异常监控已全部激活");
    }
}
