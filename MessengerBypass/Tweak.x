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

static NSString *mb_hex_dump(const void *data, size_t length, size_t maxLen) {
    if (!data || length == 0) return @"(empty)";
    size_t dumpLen = length < maxLen ? length : maxLen;
    const uint8_t *bytes = (const uint8_t *)data;
    NSMutableString *hexStr = [NSMutableString stringWithCapacity:dumpLen * 2];
    for (size_t i = 0; i < dumpLen; i++) {
        [hexStr appendFormat:@"%02x", bytes[i]];
    }
    if (length > maxLen) {
        [hexStr appendFormat:@"...(共 %zu 字节)", length];
    }
    return hexStr;
}

// ============================================================================
// E2EE 交叉验证辅助工具 (Cross-Validation Helpers)
//   用于验证 Java 侧逆向实现与真机二进制的差异结论:
//     结论#1: DGW 帧格式 (Java 自造 0xD657 魔数) —— 在出站流量中搜索真实框帧
//     结论#2: 加密明文信封结构 (Java 单层 135B 信封) —— 解析 protobuf 顶层字段
//     结论#3: Franking 签名 (Java 缺失) —— 捕获 franking_tag/reporting_tag/franking_key
//     结论#4: 设备公钥在线拉取 (Java 靠预导入) —— hook Minos/TAM 设备发现
//     结论#5: libsignal C API 与群聊 sender_key —— hook prekey/sender_key store
// ============================================================================

// 解析 protobuf 顶层字段布局 (仅遍历第一层, 不递归), 输出如 "[F1 LEN=62] [F2 LEN=69]"
static NSString *mb_parse_protobuf_top_level(const uint8_t *data, size_t len) {
    if (!data || len == 0) return @"(empty)";
    NSMutableString *s = [NSMutableString string];
    size_t i = 0;
    int fieldCount = 0;
    while (i < len && fieldCount < 32) {
        uint64_t tag = 0; int shift = 0;
        while (i < len && shift < 64) {
            uint8_t b = data[i++];
            tag |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        int fieldNum = (int)(tag >> 3);
        int wireType = (int)(tag & 0x7);
        if (fieldNum == 0) break;
        if (wireType == 2) {
            uint64_t vlen = 0; int sh = 0;
            while (i < len && sh < 64) { uint8_t b = data[i++]; vlen |= (uint64_t)(b & 0x7f) << sh; if (!(b & 0x80)) break; sh += 7; }
            [s appendFormat:@"[F%d LEN=%llu] ", fieldNum, (unsigned long long)vlen];
            if (i + vlen > len) { [s appendString:@"(截断)"]; break; }
            i += vlen;
        } else if (wireType == 0) {
            uint64_t v = 0; int sh = 0;
            while (i < len && sh < 64) { uint8_t b = data[i++]; v |= (uint64_t)(b & 0x7f) << sh; if (!(b & 0x80)) break; sh += 7; }
            [s appendFormat:@"[F%d VARINT=%llu] ", fieldNum, (unsigned long long)v];
        } else if (wireType == 5) { i += 4; [s appendFormat:@"[F%d I32] ", fieldNum]; }
        else if (wireType == 1) { i += 8; [s appendFormat:@"[F%d I64] ", fieldNum]; }
        else { [s appendFormat:@"[F%d WT%d 非法] ", fieldNum, wireType]; break; }
        fieldCount++;
    }
    return s;
}

// 最近一次 Signal 加密输出的密文指纹 (用于在出站 TLS/socket 流量中定位真实框帧)
static os_unfair_lock g_cipher_lock = OS_UNFAIR_LOCK_INIT;
static uint8_t g_last_cipher[32];
static size_t g_last_cipher_len = 0;

static void mb_remember_cipher(const uint8_t *c, size_t n) {
    if (!c || n < 8) return;
    os_unfair_lock_lock(&g_cipher_lock);
    size_t copy = n < sizeof(g_last_cipher) ? n : sizeof(g_last_cipher);
    memcpy(g_last_cipher, c, copy);
    g_last_cipher_len = copy;
    os_unfair_lock_unlock(&g_cipher_lock);
}

// 在出站帧中分析真实 DGW 封装: 检测 0xD657/zstd 魔数, 定位 Signal 密文并 dump 其外层框帧头
static void mb_analyze_outbound_frame(const char *chan, const uint8_t *b, size_t n) {
    if (!b || n < 4) return;

    BOOL hasD657 = (b[0] == 0xD6 && b[1] == 0x57);
    if (hasD657) {
        MBLogI(@"E2EE-VERIFY", @"[结论#1][DGW帧] ⚠️⚠️ %s 出站帧以 0xD657 开头 —— 与 Java MccwDgwStreamFrame 自造魔数一致! 大小=%zu | Hex: %@",
               chan, n, mb_hex_dump(b, n, 64));
    }

    // 定位最近的 Signal 密文, 揭示其真实外层封装 (框帧头在密文之前的字节)
    os_unfair_lock_lock(&g_cipher_lock);
    size_t clen = g_last_cipher_len;
    uint8_t needle[32];
    if (clen >= 8) memcpy(needle, g_last_cipher, clen);
    os_unfair_lock_unlock(&g_cipher_lock);

    if (clen >= 8 && n >= clen) {
        void *hit = memmem(b, n, needle, clen < 12 ? clen : 12);
        if (hit) {
            size_t off = (size_t)((const uint8_t *)hit - b);
            size_t hdrStart = off > 48 ? off - 48 : 0;
            size_t hdrLen = off - hdrStart;
            MBLogI(@"E2EE-VERIFY", @"[结论#1][DGW帧] ✅ 在 %s 出站帧中定位到 Signal 密文! 偏移=%zu 帧总长=%zu D657=%d",
                   chan, off, n, hasD657);
            MBLogI(@"E2EE-VERIFY", @"[结论#1][DGW帧] 密文前 %zu 字节真实框帧头(揭示真实封装格式): %@",
                   hdrLen, hdrLen > 0 ? mb_hex_dump(b + hdrStart, hdrLen, 48) : @"(密文在帧首,无自定义帧头)");
        }
    }
}

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

// ----------------------------------------------------------------------------
// Messenger 应用层证书固定 (SPKI pinning) 绕过: MBICertPinning*。
//   静态分析确认这些是导出符号, 且发生在 SecTrust / mbedtls 链校验之前——所以只放行 SecTrust /
//   mbedtls 不够, netguard 的 MITM 证书仍被 pinning 拒 (2 字节 alert, 连 graph 都拒)。
//   这里让 pinning 配置读取返回 NULL(无固定项 -> 跳过固定), 并让挑战处理器直接 UseCredential 放行。
// ----------------------------------------------------------------------------
typedef void* (*MBIGetCertificatePinning_t)(void);
static MBIGetCertificatePinning_t orig_MBIGetCertificatePinning = NULL;
static void* my_MBIGetCertificatePinning(void) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"🚫 MBIGetCertificatePinning -> NULL (禁用固定配置)");
    return NULL;
}

typedef void* (*MBIGetCertificatePinningFromBundles_t)(void);
static MBIGetCertificatePinningFromBundles_t orig_MBIGetCertificatePinningFromBundles = NULL;
static void* my_MBIGetCertificatePinningFromBundles(void) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"🚫 MBIGetCertificatePinningFromBundles -> NULL (禁用固定配置)");
    return NULL;
}

typedef void (^MBIChallengeCompletion)(NSURLSessionAuthChallengeDisposition, NSURLCredential *);
typedef void (*MBICertPinningHandleChallenge_t)(NSURLAuthenticationChallenge *, MBIChallengeCompletion);
static MBICertPinningHandleChallenge_t orig_MBICertPinningHandleChallenge = NULL;
static void my_MBICertPinningHandleChallenge(NSURLAuthenticationChallenge *challenge, MBIChallengeCompletion completion) {
    @try {
        SecTrustRef trust = challenge.protectionSpace.serverTrust;
        MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning",
                         @"🚫 MBICertPinningHandleChallenge -> UseCredential 放行 host=%@",
                         challenge.protectionSpace.host);
        if (completion) {
            if (trust) {
                completion(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:trust]);
            } else {
                completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            }
        }
    } @catch (__unused NSException *e) {
        if (completion) completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
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

typedef int (*SSL_write_ptr_t)(void *ssl, const void *buf, int num);
static SSL_write_ptr_t orig_SSL_write = NULL;

typedef int (*SSL_read_ptr_t)(void *ssl, void *buf, int num);
static SSL_read_ptr_t orig_SSL_read = NULL;

static int my_SSL_write(void *ssl, const void *buf, int num) {
    if (buf && num > 0) {
        const uint8_t *b = (const uint8_t *)buf;
        // 捕获心跳 (37B)、发信帧 (53B-300B) 或建连帧 (5000B+)
        if (num == 37 || num == 53 || num == 69 || num > 500 || (num > 20 && b[0] == 0x0a)) {
            MBLogI(@"DGW_SSL_WRITE", @"🚀 [BoringSSL Write] 大小: %d 字节 | 前部 Hex: %@",
                   num, mb_hex_dump(buf, num, 128));
        }
        if (num > 16) mb_analyze_outbound_frame("SSL_write", b, (size_t)num);
    }
    return orig_SSL_write ? orig_SSL_write(ssl, buf, num) : -1;
}

static int my_SSL_read(void *ssl, void *buf, int num) {
    int res = orig_SSL_read ? orig_SSL_read(ssl, buf, num) : -1;
    if (res > 0 && buf) {
        const uint8_t *b = (const uint8_t *)buf;
        if (res == 39 || res == 41 || res == 70 || res > 200) {
            MBLogI(@"DGW_SSL_READ", @"📥 [BoringSSL Read] 大小: %d 字节 | 前部 Hex: %@",
                   res, mb_hex_dump(buf, res, 128));
        }
    }
    return res;
}

// ----------------------------------------------------------------------------
// MQTT/MNS 明文抓取: 定向 hook LightSpeedEngine 内【静态链接 BoringSSL】的 SSL_write/SSL_read
//   Tigon 到 gateway.facebook.com:443 的 MQTT-over-TLS 用 LightSpeedEngine 自带静态 BoringSSL
//   (导出 _SSL_write@0xd1add4 / _SSL_read@0xd1adc4)。全局 dlsym 命中的是别的镜像 SSL_write, 抓不到;
//   这里用 dlopen(name, RTLD_NOLOAD) 拿到 LightSpeedEngine handle 再 dlsym, 精确 hook 到它自己的
//   SSL_write —— 即可在 TLS 加密前拿到 MQTT CONNECT/PUBLISH 明文帧。
//   按 MQTT 控制报文类型过滤, 避开 graph.facebook.com 的 HTTP/2 噪声 (其帧首多为 0x00 长度字节)。
// ----------------------------------------------------------------------------
static const char *mqtt_pkt_name(uint8_t b) {
    switch (b & 0xF0) {
        case 0x10: return "CONNECT";
        case 0x20: return "CONNACK";
        case 0x30: return "PUBLISH";
        case 0x40: return "PUBACK";
        case 0x50: return "PUBREC";
        case 0x60: return "PUBREL";
        case 0x70: return "PUBCOMP";
        case 0x80: return "SUBSCRIBE";
        case 0x90: return "SUBACK";
        case 0xA0: return "UNSUBSCRIBE";
        case 0xB0: return "UNSUBACK";
        case 0xC0: return "PINGREQ";
        case 0xD0: return "PINGRESP";
        case 0xE0: return "DISCONNECT";
        default: return "?";
    }
}
// MQTT 控制报文首字节高半字节判定 (排除 HTTP/2: 其 DATA/HEADERS 帧首字节多为 0x00 长度高位)
static BOOL mqtt_like(uint8_t t) {
    switch (t & 0xF0) {
        case 0x10: case 0x20: case 0x30: case 0x40:
        case 0x80: case 0x90: case 0xA0: case 0xB0:
        case 0xC0: case 0xD0: case 0xE0: return YES;
        default: return NO;
    }
}

// MNS_FIRST 实现见下方; 这里前向声明供 LSE SSL_write / nw_send / ALPN 在武装窗口内 dump 首帧
static int mb_mns_capture_armed(void);
static void mb_dump_first_frame(const char *chan, void *conn, const void *buf, size_t len);
static void mb_arm_mns_first_frame(const char *reason, NSString *host);

typedef int (*SSL_rw_ptr_t)(void *ssl, const void *buf, int num);
static SSL_rw_ptr_t orig_LSE_SSL_write = NULL;
static SSL_rw_ptr_t orig_LSE_SSL_read  = NULL;
static int g_mqtt_tx = 0, g_mqtt_rx = 0;
static int g_lse_w_total = 0;

// BoringSSL: int SSL_set_alpn_protos(SSL*, const uint8_t *protos, unsigned len);
// protos = 长度前缀列表, 例如 02 68 32 = "h2"
typedef int (*ssl_set_alpn_t)(void *ssl, const uint8_t *protos, unsigned len);
static ssl_set_alpn_t orig_LSE_SSL_set_alpn = NULL;
static int my_LSE_SSL_set_alpn(void *ssl, const uint8_t *protos, unsigned len) {
    @try {
        if (protos && len > 0 && len < 256) {
            NSMutableString *list = [NSMutableString string];
            unsigned i = 0;
            while (i < len) {
                unsigned l = protos[i++];
                if (i + l > len) break;
                NSString *p = [[NSString alloc] initWithBytes:protos + i length:l encoding:NSUTF8StringEncoding];
                if (list.length) [list appendString:@","];
                [list appendString:p ?: @"?"];
                i += l;
            }
            MBLogI(@"MNS_ALPN", @"🔐 SSL_set_alpn_protos ssl=%p => [%@] rawHex=%@",
                   ssl, list, mb_hex_dump(protos, (int)len, 64));
            // 仅 mqtt 相关才武装; 勿对纯 h2 武装(会刷爆无关连接)
            if ([list.lowercaseString containsString:@"mqtt"]) {
                mb_arm_mns_first_frame("SSL_set_alpn", list);
            }
        }
    } @catch (__unused NSException *e) {}
    return orig_LSE_SSL_set_alpn ? orig_LSE_SSL_set_alpn(ssl, protos, len) : 0;
}

static int my_LSE_SSL_write(void *ssl, const void *buf, int num) {
    @try {
        if (buf && num > 0) {
            if (mb_mns_capture_armed()) {
                mb_dump_first_frame("LSE_SSL_write", ssl, buf, (size_t)num);
            }
            uint8_t t = ((const uint8_t *)buf)[0];
            int tot = ++g_lse_w_total;
            if (tot <= 20 || (tot % 256) == 0) {
                MBLogI(@"LSE_DIAG", @"[LSE SSL_write] tot=%d firstByte=0x%02x len=%d ssl=%p", tot, t, num, ssl);
            }
            if (mqtt_like(t)) {
                int n = num > 700 ? 700 : num;
                MBLogI(@"MQTT_TX", @"📤 [LSE SSL_write] #%d type=0x%02x(%s) len=%d ssl=%p | Hex: %@",
                       ++g_mqtt_tx, t, mqtt_pkt_name(t), num, ssl, mb_hex_dump(buf, n, 700));
            }
        }
    } @catch (__unused NSException *e) {}
    return orig_LSE_SSL_write(ssl, buf, num);
}

static int my_LSE_SSL_read(void *ssl, const void *buf, int num) {
    int res = orig_LSE_SSL_read(ssl, buf, num);
    @try {
        if (res > 0 && buf) {
            uint8_t t = ((const uint8_t *)buf)[0];
            if (mqtt_like(t)) {
                int n = res > 700 ? 700 : res;
                MBLogI(@"MQTT_RX", @"📥 [LSE SSL_read] #%d type=0x%02x(%s) len=%d ssl=%p | Hex: %@",
                       ++g_mqtt_rx, t, mqtt_pkt_name(t), res, ssl, mb_hex_dump(buf, n, 700));
            }
        }
    } @catch (__unused NSException *e) {}
    return res;
}

static void hook_lse_boringssl(void) {
    if (orig_LSE_SSL_write && orig_LSE_SSL_read && orig_LSE_SSL_set_alpn) return;
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "LightSpeedEngine")) continue;
        void *h = dlopen(name, RTLD_NOLOAD);
        if (!h) { MBLogW(@"MQTT", @"⚠️ dlopen(LightSpeedEngine,NOLOAD) 失败"); return; }
        if (!orig_LSE_SSL_write) {
            void *w = dlsym(h, "SSL_write");
            if (w) { MSHookFunction(w, (void *)my_LSE_SSL_write, (void **)&orig_LSE_SSL_write);
                     MBLogI(@"MQTT", @"✅ 定向挂钩 LightSpeedEngine SSL_write (MQTT 明文发送): %p", w); }
            else MBLogW(@"MQTT", @"⚠️ LightSpeedEngine 无 SSL_write 导出");
        }
        if (!orig_LSE_SSL_read) {
            void *r = dlsym(h, "SSL_read");
            if (r) { MSHookFunction(r, (void *)my_LSE_SSL_read, (void **)&orig_LSE_SSL_read);
                     MBLogI(@"MQTT", @"✅ 定向挂钩 LightSpeedEngine SSL_read (MQTT 明文接收): %p", r); }
        }
        if (!orig_LSE_SSL_set_alpn) {
            void *a = dlsym(h, "SSL_set_alpn_protos");
            if (a) { MSHookFunction(a, (void *)my_LSE_SSL_set_alpn, (void **)&orig_LSE_SSL_set_alpn);
                     MBLogI(@"MQTT", @"✅ 定向挂钩 LightSpeedEngine SSL_set_alpn_protos (ALPN 列表): %p", a); }
            else MBLogW(@"MQTT", @"⚠️ LightSpeedEngine 无 SSL_set_alpn_protos");
        }
        return;
    }
}

// ----------------------------------------------------------------------------
// MNS/Fizz pinning 精确绕过: MNS 走 Fizz, 证书链校验用 LightSpeedEngine 自带【静态 BoringSSL】的
//   X509_verify_cert(0x64ab44, 已导出) 配 Meta 私有根证书库 —— 全局 dlsym 的 X509_verify_cert
//   盖不到 LSE 内部这份, 故此前 netguard MITM 伪造证书一直被 pinning 拒(MNS 每 5s 重连, AEAD 2字节 alert)。
//   这里 dlopen(NOLOAD)+dlsym 精确命中 LSE 内部那份, 强制放行链校验, 让 MITM 证书链通过 -> 可解密整条 MNS。
//   顺带把 getUseMbedtlsCertificateVerifier 打日志, 判定 MNS 用的是 Fizz-OpenSSL 还是 mbedtls 校验器。
// ----------------------------------------------------------------------------
static X509_verify_cert_ptr_t orig_LSE_X509_verify_cert = NULL;
static int my_LSE_X509_verify_cert(void *ctx) {
    MBLogRateLimited(2.0, MBLogLevelInfo, @"SSL-Pinning", @"✅ [LSE] 强制通过 X509_verify_cert (MNS/Fizz 链校验)");
    return 1;
}
static SSL_get_verify_result_ptr_t orig_LSE_SSL_get_verify_result = NULL;
static long my_LSE_SSL_get_verify_result(const void *ssl) {
    return 0; // X509_V_OK
}
typedef bool (*getUseMbedtls_t)(void *self);
static getUseMbedtls_t orig_getUseMbedtls = NULL;
static bool my_getUseMbedtls(void *self) {
    bool o = orig_getUseMbedtls ? orig_getUseMbedtls(self) : false;
    MBLogRateLimited(5.0, MBLogLevelInfo, @"SSL-Pinning",
                     @"🔎 [LSE] SecureTCPSettings::getUseMbedtlsCertificateVerifier = %d (MNS 证书校验器判定)", o);
    return o; // 只观测, 不改; 若判定为 false(用 Fizz-OpenSSL) 则依赖上面的 X509_verify_cert 绕过
}
typedef bool (*getEnablePoP_t)(void *self);
static getEnablePoP_t orig_getEnablePoP = NULL;
static bool my_getEnablePoP(void *self) {
    bool o = orig_getEnablePoP ? orig_getEnablePoP(self) : true;
    MBLogRateLimited(5.0, MBLogLevelInfo, @"SSL-Pinning",
                     @"🚫 [LSE] HTTPSettings::getEnableCertificateVerificationWithProofOfPossession orig=%d -> 强制 false (关 PoP pinning)", o);
    return false; // 关闭 Meta 持有证明证书校验, 让 MNS 退回可被 MITM 的标准校验
}

static void hook_lse_certpin(void) {
    if (orig_LSE_X509_verify_cert) return;
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "LightSpeedEngine")) continue;
        void *h = dlopen(name, RTLD_NOLOAD);
        if (!h) { MBLogW(@"SSL-Pinning", @"⚠️ dlopen(LightSpeedEngine,NOLOAD) 失败 (certpin)"); return; }
        void *x = dlsym(h, "X509_verify_cert");
        if (x) { MSHookFunction(x, (void *)my_LSE_X509_verify_cert, (void **)&orig_LSE_X509_verify_cert);
                 MBLogI(@"SSL-Pinning", @"✅ 定向挂钩 LSE X509_verify_cert (MNS pinning 绕过): %p", x); }
        else MBLogW(@"SSL-Pinning", @"⚠️ LSE 无 X509_verify_cert 导出");
        void *g = dlsym(h, "SSL_get_verify_result");
        if (g) { MSHookFunction(g, (void *)my_LSE_SSL_get_verify_result, (void **)&orig_LSE_SSL_get_verify_result);
                 MBLogI(@"SSL-Pinning", @"✅ 定向挂钩 LSE SSL_get_verify_result: %p", g); }
        void *m = dlsym(h, "_ZNK8crossapp9tigonhttp3mns17SecureTCPSettings32getUseMbedtlsCertificateVerifierEv");
        if (m) { MSHookFunction(m, (void *)my_getUseMbedtls, (void **)&orig_getUseMbedtls);
                 MBLogI(@"SSL-Pinning", @"✅ 定向挂钩 LSE getUseMbedtlsCertificateVerifier (仅观测): %p", m); }
        void *p = dlsym(h, "_ZNK8crossapp9tigonhttp3mns12HTTPSettings53getEnableCertificateVerificationWithProofOfPossessionEv");
        if (p) { MSHookFunction(p, (void *)my_getEnablePoP, (void **)&orig_getEnablePoP);
                 MBLogI(@"SSL-Pinning", @"✅ 定向挂钩 LSE getEnableCertVerifWithPoP -> false (关 MNS PoP pinning): %p", p); }
        else MBLogW(@"SSL-Pinning", @"⚠️ LSE 无 getEnableCertVerifWithPoP 导出");
        return;
    }
    MBLogW(@"SSL-Pinning", @"⚠️ LightSpeedEngine 未加载, MNS certpin hook 未安装");
}

// ----------------------------------------------------------------------------
// MQTT/MNS 明文抓取 (Fizz AEAD 前明文记录): 传输 TLS 是 Meta 自研 Fizz(非 BoringSSL SSL_write、
//   非 Network.framework), 其 AEAD 用 fizz::openssl::OpenSSLEVPCipher, 底层调 BoringSSL 的
//   EVP_CipherUpdate/EVP_EncryptUpdate(导出符号)。这些函数的 in 参数 = 加密前明文 TLS 记录;
//   对 gateway MNS 连接即 MQTT 帧(尾部含 TLS1.3 inner content-type 字节)。按 MQTT 报文类型过滤。
//   必须 hook LightSpeedEngine 自带的那一份静态 BoringSSL EVP(dlopen NOLOAD + dlsym)。
// ----------------------------------------------------------------------------
typedef int (*evp_update_t)(void *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen);
static evp_update_t orig_EVP_CipherUpdate = NULL;
static evp_update_t orig_EVP_EncryptUpdate = NULL;
static int g_evp_mqtt = 0;
static int g_evp_cu_total = 0, g_evp_eu_total = 0;

static int my_EVP_CipherUpdate(void *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen) {
    @try {
        if (out && in && inlen >= 2) {  // out!=NULL => 明文数据 (AAD 调用时 out==NULL)
            int tot = ++g_evp_cu_total;
            uint8_t t = in[0];
            if (mb_mns_capture_armed()) {
                mb_dump_first_frame("EVP_CipherUpdate", ctx, in, (size_t)inlen);
            } else if (tot <= 60 || (tot % 100) == 0) {
                MBLogI(@"EVP_DIAG", @"[EVP_CipherUpdate] tot=%d firstByte=0x%02x len=%d | Hex: %@",
                       tot, t, inlen, mb_hex_dump(in, inlen > 32 ? 32 : inlen, 32));
            }
            if ((mqtt_like(t) || t == 0x0a || (inlen >= 24 && inlen <= 8192)) && g_evp_mqtt < 500) {
                int n = inlen > 800 ? 800 : inlen;
                MBLogI(@"DGW_EVP", @"🔓 [EVP_CipherUpdate 明文] #%d firstByte=0x%02x(%s) len=%d | Hex: %@",
                       ++g_evp_mqtt, t, mqtt_pkt_name(t), inlen, mb_hex_dump(in, n, 800));
            }
        }
    } @catch (__unused NSException *e) {}
    return orig_EVP_CipherUpdate(ctx, out, outlen, in, inlen);
}
static int my_EVP_EncryptUpdate(void *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen) {
    @try {
        if (out && in && inlen >= 2) {
            int tot = ++g_evp_eu_total;
            uint8_t t = in[0];
            if (mb_mns_capture_armed()) {
                mb_dump_first_frame("EVP_EncryptUpdate", ctx, in, (size_t)inlen);
            } else if (tot <= 60 || (tot % 100) == 0) {
                MBLogI(@"EVP_DIAG", @"[EVP_EncryptUpdate] tot=%d firstByte=0x%02x len=%d | Hex: %@",
                       tot, t, inlen, mb_hex_dump(in, inlen > 32 ? 32 : inlen, 32));
            }
            if ((mqtt_like(t) || t == 0x0a || (inlen >= 24 && inlen <= 8192)) && g_evp_mqtt < 500) {
                int n = inlen > 800 ? 800 : inlen;
                MBLogI(@"DGW_EVP", @"🔓 [EVP_EncryptUpdate 明文] #%d firstByte=0x%02x(%s) len=%d | Hex: %@",
                       ++g_evp_mqtt, t, mqtt_pkt_name(t), inlen, mb_hex_dump(in, n, 800));
            }
        }
    } @catch (__unused NSException *e) {}
    return orig_EVP_EncryptUpdate(ctx, out, outlen, in, inlen);
}

static void hook_lse_evp(void) {
    if (orig_EVP_CipherUpdate && orig_EVP_EncryptUpdate) return;
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "LightSpeedEngine")) continue;
        void *h = dlopen(name, RTLD_NOLOAD);
        if (!h) return;
        const void *base = _dyld_get_image_header(i);
        MBLogI(@"EVPC", @"📍 LightSpeedEngine 加载基址 base=%p (slide=%p)", base, (void *)_dyld_get_image_vmaddr_slide(i));
        if (!orig_EVP_CipherUpdate) {
            void *fn = dlsym(h, "EVP_CipherUpdate");
            if (fn) { MSHookFunction(fn, (void *)my_EVP_CipherUpdate, (void **)&orig_EVP_CipherUpdate);
                      MBLogI(@"MQTT", @"✅ 定向挂钩 LightSpeedEngine EVP_CipherUpdate (Fizz AEAD 前明文): %p", fn); }
        }
        if (!orig_EVP_EncryptUpdate) {
            void *fn = dlsym(h, "EVP_EncryptUpdate");
            if (fn) { MSHookFunction(fn, (void *)my_EVP_EncryptUpdate, (void **)&orig_EVP_EncryptUpdate);
                      MBLogI(@"MQTT", @"✅ 定向挂钩 LightSpeedEngine EVP_EncryptUpdate (Fizz AEAD 前明文): %p", fn); }
        }
        return;
    }
}

// ----------------------------------------------------------------------------
// vtable 路线: hook 导出的 fizz::openssl::OpenSSLEVPCipher::create 拿到 cipher 对象, dump 其 vtable
//   前若干槽位的运行时地址。离线用 (slot - base) 得到文件偏移, 反汇编定位 encrypt(调 AES-GCM 的那个)
//   槽位, 再按偏移 hook 该 encrypt —— 即可拿到 AEAD 前明文 TLS 记录 (= MQTT 帧)。
// ----------------------------------------------------------------------------
typedef void (*evpc_create_t)(void *out_uptr, void *err, unsigned long a, unsigned long b,
                              unsigned long cc, const void *cipher, bool d, bool e);
static evpc_create_t orig_EVPCipher_create = NULL;
static int g_evpc_create = 0;
static void my_EVPCipher_create(void *out_uptr, void *err, unsigned long a, unsigned long b,
                                unsigned long cc, const void *cipher, bool d, bool e) {
    orig_EVPCipher_create(out_uptr, err, a, b, cc, cipher, d, e);
    @try {
        void *obj = out_uptr ? *(void **)out_uptr : NULL;     // unique_ptr 首成员 = 裸指针
        void *vt  = obj ? *(void **)obj : NULL;               // 对象首字段 = vtable 指针
        int idx = ++g_evpc_create;
        if (vt && idx <= 4) {
            void **v = (void **)vt;
            MBLogI(@"EVPC", @"🧬 OpenSSLEVPCipher::create #%d obj=%p vt=%p keyLen=%lu | slots[0..9]: %p %p %p %p %p %p %p %p %p %p",
                   idx, obj, vt, a, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9]);
        }
    } @catch (__unused NSException *e) {}
}

static void hook_evpcipher_create(void) __attribute__((unused));
static void hook_evpcipher_create(void) {
    if (orig_EVPCipher_create) return;
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "LightSpeedEngine")) continue;
        void *h = dlopen(name, RTLD_NOLOAD);
        if (!h) return;
        void *fn = dlsym(h, "_ZN4fizz7openssl16OpenSSLEVPCipher6createERNSt3__110unique_ptrIS1_NS2_14default_deleteIS1_EEEERNS_5ErrorEmmmPK13evp_cipher_stbb");
        if (fn) { MSHookFunction(fn, (void *)my_EVPCipher_create, (void **)&orig_EVPCipher_create);
                  MBLogI(@"MQTT", @"✅ 挂钩 OpenSSLEVPCipher::create (dump vtable 定位 encrypt): %p", fn); }
        else MBLogW(@"MQTT", @"⚠️ 未找到 OpenSSLEVPCipher::create 符号");
        return;
    }
}

// ----------------------------------------------------------------------------
// MQTT/MNS 明文抓取 (Network.framework): 两个 BoringSSL SSL_write 均 0 触发 => Tigon 传输 TLS
//   走 Apple Network.framework (nw_connection), 明文边界是 nw_connection_send 的 dispatch_data content。
//   在此抓 MQTT CONNECT/PUBLISH 明文帧 (TLS 由系统在下层加密)。用 dispatch_data_apply 只读首个 region,
//   不产生需释放的对象, 避开 ARC/MRC 释放问题。
// ----------------------------------------------------------------------------
typedef void (*nw_conn_send_t)(void *conn, void *content, void *ctx, bool is_complete, void (^completion)(void *));
static nw_conn_send_t orig_nw_connection_send = NULL;
static int g_nw_tx = 0;
static int g_nw_total = 0;
static void my_nw_connection_send(void *conn, void *content, void *ctx, bool is_complete, void (^completion)(void *)) {
    @try {
        if (content) {
            dispatch_data_apply((__bridge dispatch_data_t)content, ^bool(dispatch_data_t region, size_t off, const void *buf, size_t size) {
                if (buf && size > 0) {
                    // gateway 走 MNS SecureTCP/Fizz, 不经 nw_connection_send;
                    // 武装窗口内全量 dump 会把 graph/www H2 与系统小包刷爆日志, 已关闭。
                    uint8_t t = ((const uint8_t *)buf)[0];
                    int tot = ++g_nw_total;
                    if (tot <= 20 || (tot % 256) == 0) {
                        MBLogI(@"NW_DIAG", @"[nw_send] tot=%d firstByte=0x%02x size=%zu conn=%p", tot, t, size, conn);
                    }
                    if (mqtt_like(t)) {
                        int n = size > 700 ? 700 : (int)size;
                        MBLogI(@"MQTT_NW_TX", @"📤 [nw_connection_send] #%d type=0x%02x(%s) regionLen=%zu conn=%p | Hex: %@",
                               ++g_nw_tx, t, mqtt_pkt_name(t), size, conn, mb_hex_dump(buf, n, 700));
                    }
                }
                return false;
            });
        }
    } @catch (__unused NSException *e) {}
    orig_nw_connection_send(conn, content, ctx, is_complete, completion);
}

static void hook_nw_connection_send(void) {
    if (orig_nw_connection_send) return;
    void *fn = dlsym(RTLD_DEFAULT, "nw_connection_send");
    if (fn) {
        MSHookFunction(fn, (void *)my_nw_connection_send, (void **)&orig_nw_connection_send);
        MBLogI(@"MQTT", @"✅ 挂钩 nw_connection_send (Network.framework 明文发送): %p", fn);
    } else {
        MBLogW(@"MQTT", @"⚠️ 未找到 nw_connection_send 符号");
    }
}

// nw_connection_create(endpoint, params) -> 记录 endpoint 主机名与返回的 conn 指针, 用于把
// nw_connection_send 的 conn 反查到目标 host (定位 gateway.facebook.com 的 MQTT 连接)。
typedef void *(*nw_conn_create_t)(void *endpoint, void *params);
typedef const char *(*nw_ep_hostname_t)(void *endpoint);
typedef const char *(*nw_ep_port_t)(void *endpoint);
static nw_conn_create_t orig_nw_connection_create = NULL;
static nw_ep_hostname_t p_nw_endpoint_get_hostname = NULL;
static nw_ep_port_t p_nw_endpoint_get_port = NULL;
// 前方声明: gateway 建连后武装首帧抓取窗口
static void mb_arm_mns_first_frame(const char *reason, NSString *host);

static void *my_nw_connection_create(void *endpoint, void *params) {
    void *conn = orig_nw_connection_create(endpoint, params);
    @try {
        const char *host = (endpoint && p_nw_endpoint_get_hostname) ? p_nw_endpoint_get_hostname(endpoint) : NULL;
        MBLogI(@"NW_MAP", @"🔗 [nw_connection_create] conn=%p host=%s", conn, host ? host : "(null)");
        if (host && strstr(host, "gateway.facebook.com")) {
            mb_arm_mns_first_frame("nw_connection_create", [NSString stringWithUTF8String:host]);
        }
    } @catch (__unused NSException *e) {}
    return conn;
}

static void hook_nw_connection_create(void) {
    if (orig_nw_connection_create) return;
    if (!p_nw_endpoint_get_hostname) p_nw_endpoint_get_hostname = (nw_ep_hostname_t)dlsym(RTLD_DEFAULT, "nw_endpoint_get_hostname");
    void *fn = dlsym(RTLD_DEFAULT, "nw_connection_create");
    if (fn) {
        MSHookFunction(fn, (void *)my_nw_connection_create, (void **)&orig_nw_connection_create);
        MBLogI(@"MQTT", @"✅ 挂钩 nw_connection_create (endpoint→conn 映射): %p", fn);
    } else {
        MBLogW(@"MQTT", @"⚠️ 未找到 nw_connection_create 符号");
    }
}

// ----------------------------------------------------------------------------
// MNS 传输层抓取 (Tigon): 判定 MNS 发送走 Secure-TCP 还是 QUIC, 并抓 endpoint / 请求
//   MNS 由 facebook::tigon::mns 实现, 定义在 LightSpeedEngine (符号已导出, dlsym 可取)。
//   关键: 若 MNSSecureTCPConnectionEstablish 触发 => MNS 走 TCP (Java 可复刻)；
//         若只 SendRequest 触发而 establish 不触发 => 走 QUIC。
//   MCFString/MCFURL/MCFData 均与 CoreFoundation toll-free 桥接 (已反汇编验证:
//     MCFStringGetCString→CFStringGetCString, MCFURLGetString→CFURLGetString),
//   故可直接 (__bridge id) 打印, 安全。
// ----------------------------------------------------------------------------
#define MNS_SYM_SECURETCP_ESTABLISH "_Z31MNSSecureTCPConnectionEstablishP24__MNSSecureTCPConnectionP16__MNSDNSResolverPK11__MCFStringiNSt3__16vectorIN8crossapp9tigonhttp3mns13SocketAddressENS6_9allocatorISB_EEEE"
#define MNS_SYM_TCP_ESTABLISH       "_Z25MNSTCPConnectionEstablishP18__MNSTCPConnectionP16__MNSDNSResolverPK11__MCFStringiNSt3__16vectorIN8crossapp9tigonhttp3mns13SocketAddressENS6_9allocatorISB_EEEE"
#define MNS_SYM_HTTPCLIENT_CREATE   "_Z31MNSHTTPClientCreateWithSettingsP14__MNSEventLoopS0_NSt3__110shared_ptrIN8crossapp9tigonhttp3mns12HTTPSettingsEEEPK8__MCFURLPK11__MCFString"
#define MNS_SYM_HTTPCLIENT_SEND     "_Z24MNSHTTPClientSendRequestP15__MNSHTTPClientN8crossapp9tigonhttp3mns11HTTPRequestE22MNSHTTPClientCallbacksPPKv"
#define MNS_SYM_GET_ALPN            "_ZNK8crossapp9tigonhttp3mns17SecureTCPSettings15getALPNProtocolEv"

// ---- gateway 建连首帧抓取窗口 (对比 Java H2/MQTT 差异) ----
static volatile int64_t g_mns_capture_until_ms = 0;
static volatile int g_mns_capture_n = 0;
static const int g_mns_capture_max = 48;
static void *g_mns_gateway_conn = NULL;

static int64_t mb_now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
static int mb_mns_capture_armed(void) {
    return mb_now_ms() < g_mns_capture_until_ms && g_mns_capture_n < g_mns_capture_max;
}
static void mb_arm_mns_first_frame(const char *reason, NSString *host) {
    g_mns_capture_until_ms = mb_now_ms() + 25000; // 25s 窗口
    g_mns_capture_n = 0;
    MBLogI(@"MNS_FIRST", @"🎯 武装首帧抓取 25s reason=%s host=%@ (对比 Java CONNECT/H2)", reason, host ?: @"(null)");
}
static NSString *mb_classify_app_bytes(const void *buf, size_t len) {
    if (!buf || len < 1) return @"empty";
    const uint8_t *p = (const uint8_t *)buf;
    if (len >= 24 && memcmp(p, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) return @"H2_PREFACE";
    if (len >= 9 && p[3] == 0x04) return @"H2_SETTINGS?";
    if (len >= 9 && p[3] == 0x01) return @"H2_HEADERS?";
    if (len >= 9 && p[3] == 0x00) return @"H2_DATA?";
    uint8_t t = (uint8_t)(p[0] >> 4);
    if (t == 1) return @"MQTT_CONNECT?";
    if (t == 3) return @"MQTT_PUBLISH?";
    if (t == 8) return @"MQTT_SUBSCRIBE?";
    if (t == 12) return @"MQTT_PINGREQ?";
    if (p[0] == 0x16) return @"TLS_Handshake";
    if (p[0] == 0x17) return @"TLS_AppData";
    if (p[0] == 0x14) return @"TLS_CCS";
    return @"OTHER";
}
static void mb_dump_first_frame(const char *chan, void *conn, const void *buf, size_t len) {
    if (!mb_mns_capture_armed()) return;
    if (!buf || len == 0) {
        MBLogI(@"MNS_FIRST", @"📤 [%s] #%d conn=%p len=0", chan, ++g_mns_capture_n, conn);
        return;
    }
    int n = (int)(len > 1024 ? 1024 : len);
    NSString *cls = mb_classify_app_bytes(buf, len);
    MBLogI(@"MNS_FIRST", @"📤 [%s] #%d conn=%p len=%zu class=%@ | Hex: %@",
           chan, ++g_mns_capture_n, conn, len, cls, mb_hex_dump(buf, n, 1024));
    // ASCII 辅助 (H2 preface / header names)
    NSMutableString *asc = [NSMutableString stringWithCapacity:n];
    for (int i = 0; i < n; i++) {
        int c = ((const uint8_t *)buf)[i];
        [asc appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
    }
    MBLogI(@"MNS_FIRST", @"   ASC: %@", asc);
}

// MNSSecureTCPConnectionEstablish(conn, resolver, MCFString* host, int port, vector<SocketAddress>)
typedef void* (*mns_tcp_establish_t)(void *conn, void *resolver, CFStringRef host, int port, void *addrs);
static mns_tcp_establish_t orig_MNSSecureTCPConnectionEstablish = NULL;
static void* my_MNSSecureTCPConnectionEstablish(void *conn, void *resolver, CFStringRef host, int port, void *addrs) {
    @try {
        NSString *h = host ? (__bridge NSString *)host : @"(null)";
        MBLogI(@"MNS_TCP", @"🔌 [SecureTCPConnectionEstablish] conn=%p host=%@ port=%d (Secure-TCP)", conn, h, port);
        if ([h containsString:@"gateway.facebook.com"]) {
            g_mns_gateway_conn = conn;
            mb_arm_mns_first_frame("SecureTCPEstablish", h);
        }
    } @catch (__unused NSException *e) {}
    return orig_MNSSecureTCPConnectionEstablish(conn, resolver, host, port, addrs);
}

static mns_tcp_establish_t orig_MNSTCPConnectionEstablish = NULL;
static void* my_MNSTCPConnectionEstablish(void *conn, void *resolver, CFStringRef host, int port, void *addrs) {
    @try {
        NSString *h = host ? (__bridge NSString *)host : @"(null)";
        MBLogI(@"MNS_TCP", @"🔌 [TCPConnectionEstablish] conn=%p host=%@ port=%d (Plain-TCP)", conn, h, port);
        if ([h containsString:@"gateway.facebook.com"]) {
            mb_arm_mns_first_frame("PlainTCPEstablish", h);
        }
    } @catch (__unused NSException *e) {}
    return orig_MNSTCPConnectionEstablish(conn, resolver, host, port, addrs);
}

// MNSSecureTCPConnectionSend(conn, buf, len) —— 若触发则为 TLS 前应用层明文。
// 历史: 符号能 hook 但 0 触发 → 仍保留; 另用 write() 窗口兜底。
typedef long (*mns_tcp_send_t)(void *conn, const void *buf, unsigned long len);
static mns_tcp_send_t orig_MNSSecureTCPConnectionSend = NULL;
static mns_tcp_send_t orig_MNSTCPConnectionSend = NULL;
static int g_mns_stcp_send = 0;
static int g_mns_tcp_send = 0;
static long my_MNSSecureTCPConnectionSend(void *conn, const void *buf, unsigned long len) {
    // 入口仅限频记录, 避免热路径刷屏; 真正首帧走 mb_dump
    MBLogRateLimited(1.0, MBLogLevelInfo, @"MNS_STCP_SEND",
                     @"➡️ enter #%d conn=%p buf=%p len=%lu gatewayConn=%p",
                     ++g_mns_stcp_send, conn, buf, len, g_mns_gateway_conn);
    @try {
        if (buf && len > 0 && len < (16 * 1024 * 1024)) {
            mb_dump_first_frame("SecureTCPSend", conn, buf, (size_t)len);
        } else if (buf) {
            CFTypeID tid = CFGetTypeID((CFTypeRef)buf);
            if (tid == CFDataGetTypeID()) {
                CFDataRef d = (CFDataRef)buf;
                mb_dump_first_frame("SecureTCPSend/CFData", conn, CFDataGetBytePtr(d), (size_t)CFDataGetLength(d));
            }
        }
    } @catch (__unused NSException *e) {}
    return orig_MNSSecureTCPConnectionSend(conn, buf, len);
}
static long my_MNSTCPConnectionSend(void *conn, const void *buf, unsigned long len) {
    MBLogI(@"MNS_TCP_SEND", @"➡️ enter #%d conn=%p buf=%p len=%lu", ++g_mns_tcp_send, conn, buf, len);
    @try {
        if (buf && len > 0 && len < (16 * 1024 * 1024))
            mb_dump_first_frame("PlainTCPSend", conn, buf, (size_t)len);
    } @catch (__unused NSException *e) {}
    return orig_MNSTCPConnectionSend(conn, buf, len);
}

// SecureTCPSettings::getALPNProtocol() const → 返回 this 首字段 (MCFString*)
typedef CFStringRef (*mns_get_alpn_t)(void *self);
static mns_get_alpn_t orig_getALPNProtocol = NULL;
static CFStringRef my_getALPNProtocol(void *self) {
    CFStringRef s = orig_getALPNProtocol ? orig_getALPNProtocol(self) : NULL;
    @try {
        NSString *ns = s ? (__bridge NSString *)s : nil;
        MBLogRateLimited(1.0, MBLogLevelInfo, @"MNS_ALPN",
                         @"🔎 SecureTCPSettings::getALPNProtocol => '%@' settings=%p", ns ?: @"(null)", self);
    } @catch (__unused NSException *e) {}
    return s;
}

// 注意: 禁止全局 hook write()/send() —— 会在 libnetwork DNS/系统线程触发 EXC_BREAKPOINT
// (见下方 %ctor 注释)。首帧靠 SecureTCPSend / LSE SSL_write / nw_connection_send / EVP。

// MNSHTTPClientCreateWithSettings(evloop, evloop, shared_ptr<HTTPSettings>[隐式引用=1寄存器], MCFURL* url, MCFString*)
typedef void* (*mns_httpclient_create_t)(void *ev1, void *ev2, void *settings, CFURLRef url, CFStringRef extra);
static mns_httpclient_create_t orig_MNSHTTPClientCreateWithSettings = NULL;
static void* my_MNSHTTPClientCreateWithSettings(void *ev1, void *ev2, void *settings, CFURLRef url, CFStringRef extra) {
    @try {
        NSURL *u = url ? (__bridge NSURL *)url : nil;
        NSString *e2 = extra ? (__bridge NSString *)extra : nil;
        MBLogI(@"MNS_HTTP", @"🌐 [HTTPClientCreateWithSettings] MNS endpoint url=%@ extra=%@", u.absoluteString, e2);
    } @catch (__unused NSException *e) {}
    return orig_MNSHTTPClientCreateWithSettings(ev1, ev2, settings, url, extra);
}

// MNSHTTPClientSendRequest(client, HTTPRequest[隐式引用], callbacks, void**) —— 仅计数+指针, 不解析结构 (防崩)
typedef void* (*mns_httpclient_send_t)(void *client, void *req, void *callbacks, void **outTok);
static mns_httpclient_send_t orig_MNSHTTPClientSendRequest = NULL;
static int g_mns_send_count = 0;
static void* my_MNSHTTPClientSendRequest(void *client, void *req, void *callbacks, void **outTok) {
    @try {
        MBLogI(@"MNS_SEND", @"📤 [HTTPClientSendRequest] #%d client=%p reqPtr=%p (MNS 发送路径已触发)",
               ++g_mns_send_count, client, req);
    } @catch (__unused NSException *e) {}
    return orig_MNSHTTPClientSendRequest(client, req, callbacks, outTok);
}

// ----------------------------------------------------------------------------
// Fizz 写链明文抓取 (MSHookFunction, 不死锁): Frida 回溯确认 —— gateway 的 MQTT 帧走
//   LightSpeedEngine 内 Fizz 写链, 单次 flush 嵌套调用: 应用/MQTT写(0x30 区) -> TLS记录写(0x1d 区) -> socket。
//   明文 TLS 记录(=MQTT 帧)一路当参数往下传, AEAD 之前可读。Frida Interceptor 挂这些热路径内部函数
//   必死锁(arm64e+混淆无法 quiesce), 而 Substrate MSHookFunction 走另一套 trampoline, 不死锁。
//   混淆把函数切成 ~0x100B 小块; 下列偏移为 LC_FUNCTION_STARTS 缺失下反汇编定位的候选块入口。
//   用 vm_read_overwrite 安全读(非法地址返错不崩), 按精确 MQTT 控制字节 + 合法 remaining-length 过滤降噪。
// ----------------------------------------------------------------------------
// 候选写链函数入口 (相对 LightSpeedEngine 基址):
//   0x3002b8 / 0x3003bc / 0x300470 = 应用/MQTT 写区; 0x1d49f0 = TLS 记录写(AEAD 输入候选)
static const uint32_t WC_OFFSETS[] = { 0x3002b8, 0x3003bc, 0x300470, 0x1d49f0 };
static const char *WC_TAGS[]       = { "wc_3002b8", "wc_3003bc", "wc_300470", "wc_1d49f0" };
typedef void* (*wc_fn_t)(void*,void*,void*,void*,void*,void*,void*,void*);
static wc_fn_t orig_wc[4] = { NULL, NULL, NULL, NULL };
static int g_wc_calls[4] = { 0, 0, 0, 0 };
static int g_wc_hits = 0;

// 安全读: 非法地址返回 false 而非 SIGSEGV
static bool wc_safe_read(const void *addr, void *out, size_t len) {
    if (!addr) return false;
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)len, (vm_address_t)out, &got);
    return kr == KERN_SUCCESS && got == len;
}
// 精确 MQTT 控制字节 (降噪): CONNECT/CONNACK/PUBLISH(q0,q1,dup)/PUBACK/SUBSCRIBE/SUBACK/PINGREQ/PINGRESP/DISCONNECT
static const char *wc_mqtt_name(uint8_t b) {
    switch (b) {
        case 0x10: return "CONNECT"; case 0x20: return "CONNACK";
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x38: case 0x39: case 0x3a: case 0x3b: return "PUBLISH";
        case 0x40: return "PUBACK"; case 0x82: return "SUBSCRIBE"; case 0x90: return "SUBACK";
        case 0xa2: return "UNSUBSCRIBE"; case 0xb0: return "UNSUBACK";
        case 0xc0: return "PINGREQ"; case 0xd0: return "PINGRESP"; case 0xe0: return "DISCONNECT";
        default: return NULL;
    }
}
// 校验 MQTT remaining-length varint (最多 4 字节, 高位续行), 返回值长度; 返回 -1 非法
static int wc_mqtt_remlen(const uint8_t *p, int n, int *consumed) {
    int mult = 1, val = 0, i = 1;
    for (; i < n && i <= 4; i++) {
        uint8_t d = p[i];
        val += (d & 0x7f) * mult;
        if (!(d & 0x80)) { *consumed = i + 1; return val; }
        mult *= 128;
    }
    return -1;
}
// 检查一个候选缓冲: 首字节是 MQTT 控制字节 且 remaining-length 合法 且总长与读到长度自洽
static void wc_try_buf(const char *tag, const char *src, const uint8_t *buf, int n) {
    if (n < 2) return;
    const char *name = wc_mqtt_name(buf[0]);
    if (!name) return;
    int consumed = 0;
    int rem = wc_mqtt_remlen(buf, n, &consumed);
    if (rem < 0) return;
    int total = consumed + rem;
    // 降噪: 真机 gateway MQTT 帧 < 2000 字节; 拒绝过大(多为 C++ 结构数组误报)
    if (total > 2000) return;
    if (buf[0] != 0xc0 && buf[0] != 0xd0 && total < 4) return;
    // 降噪: 拒绝 "指针/结构数组" 模式 (bytes[4..8]==01000000 或 05010000)
    if (n >= 8) {
        uint32_t w1 = buf[4] | (buf[5]<<8) | (buf[6]<<16) | ((uint32_t)buf[7]<<24);
        if (w1 == 0x00000001 || w1 == 0x00000105) return;
    }
    if (g_wc_hits >= 80) return;
    g_wc_hits++;
    int dumpN = total > 0 && total < n ? total : n;
    if (dumpN > 256) dumpN = 256;
    MBLogI(@"MQTT_WC", @"🎯 [%s] %s MQTT %s remLen=%d total=%d | Hex: %@",
           tag, src, name, rem, total, mb_hex_dump(buf, dumpN, 256));
}
// folly::IOBuf 小记录 dump (data_@+0x10, length_@+0x20); 用于 TLS 记录层, 明文记录=MQTT 帧
static int g_wc_iobuf_hits = 0;
static void wc_dump_iobuf(const char *tag, const char *src, void *val) {
    if (!val) return;
    void *data = NULL; unsigned long len = 0;
    if (!wc_safe_read((const uint8_t*)val + 0x10, &data, sizeof(data))) return;
    if (!wc_safe_read((const uint8_t*)val + 0x20, &len, sizeof(len))) return;
    if (!data || len < 2 || len > 1600) return;      // 真机小记录
    uint8_t buf[1600];
    int n = len > sizeof(buf) ? (int)sizeof(buf) : (int)len;
    if (!wc_safe_read(data, buf, n)) return;
    if (g_wc_iobuf_hits >= 60) return;
    g_wc_iobuf_hits++;
    // ascii
    char asc[1601]; int m = n > 1600 ? 1600 : n;
    for (int i = 0; i < m; i++) asc[i] = (buf[i] >= 32 && buf[i] < 127) ? (char)buf[i] : '.';
    asc[m] = 0;
    MBLogI(@"MQTT_REC", @"📦 [%s] %s IOBuf len=%lu firstByte=0x%02x | ASC: %s | Hex: %@",
           tag, src, len, buf[0], [NSString stringWithUTF8String:asc], mb_hex_dump(buf, n > 200 ? 200 : n, 200));
}
// dump 一个参数寄存器: 直接 / IOBuf.data_(+0x10) / 解一层指针
static void wc_check_arg(const char *tag, int idx, void *val) {
    if (!val) return;
    uint8_t buf[256];
    char src[16];
    // (a) 直接内存
    if (wc_safe_read(val, buf, sizeof(buf))) { snprintf(src, sizeof(src), "x%d", idx); wc_try_buf(tag, src, buf, sizeof(buf)); }
    // (b) folly::IOBuf 常见: 对象 +0x10 = data_ 指针, +0x18 = length_
    void *dp = NULL;
    if (wc_safe_read((const uint8_t *)val + 0x10, &dp, sizeof(dp)) && dp) {
        if (wc_safe_read(dp, buf, sizeof(buf))) { snprintf(src, sizeof(src), "x%d.iobuf", idx); wc_try_buf(tag, src, buf, sizeof(buf)); }
    }
    // (c) 解一层指针
    void *q = NULL;
    if (wc_safe_read(val, &q, sizeof(q)) && q) {
        if (wc_safe_read(q, buf, sizeof(buf))) { snprintf(src, sizeof(src), "x%d.deref", idx); wc_try_buf(tag, src, buf, sizeof(buf)); }
    }
}
static void wc_common(int slot, void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7) {
    @try {
        int c = ++g_wc_calls[slot];
        if (c == 1 || (c % 1000) == 0) {
            MBLogI(@"MQTT_WC_DIAG", @"[%s] 调用 #%d (x1=%p x2=%p x3=%p)", WC_TAGS[slot], c, a1, a2, a3);
        }
        void *args[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
        for (int i = 0; i < 8; i++) wc_check_arg(WC_TAGS[slot], i, args[i]);
        // TLS 记录层 (slot 3 = 0x1d49f0): 额外按 folly::IOBuf 布局 dump 小明文记录
        if (slot == 3) {
            char src[16];
            for (int i = 0; i < 6; i++) { snprintf(src, sizeof(src), "x%d", i); wc_dump_iobuf(WC_TAGS[slot], src, args[i]); }
        }
    } @catch (__unused NSException *e) {}
}
#define WC_HOOK_DEF(SLOT) \
static void* my_wc_##SLOT(void *a0,void *a1,void *a2,void *a3,void *a4,void *a5,void *a6,void *a7){ \
    wc_common(SLOT, a0,a1,a2,a3,a4,a5,a6,a7); \
    return orig_wc[SLOT](a0,a1,a2,a3,a4,a5,a6,a7); }
WC_HOOK_DEF(0)
WC_HOOK_DEF(1)
WC_HOOK_DEF(2)
WC_HOOK_DEF(3)
static void* (*const WC_HOOKS[4])(void*,void*,void*,void*,void*,void*,void*,void*) = { my_wc_0, my_wc_1, my_wc_2, my_wc_3 };

static void hook_lse_writechain(void) {
    if (orig_wc[0]) return;
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "LightSpeedEngine")) continue;
        const uint8_t *base = (const uint8_t *)_dyld_get_image_header(i);
        MBLogI(@"MQTT_WC", @"📍 LightSpeedEngine base=%p — 安装 Fizz 写链明文 hook (MSHookFunction)", base);
        for (int s = 0; s < 4; s++) {
            void *fn = (void *)(base + WC_OFFSETS[s]);
            MSHookFunction(fn, (void *)WC_HOOKS[s], (void **)&orig_wc[s]);
            MBLogI(@"MQTT_WC", @"✅ hook %s @ base+0x%x = %p", WC_TAGS[s], WC_OFFSETS[s], fn);
        }
        return;
    }
    MBLogW(@"MQTT_WC", @"⚠️ LightSpeedEngine 未加载, 写链 hook 未安装");
}

static void try_hook_ssl_symbols(void) {
    hook_lse_boringssl();
    hook_lse_evp();
    hook_lse_certpin();  // MNS/Fizz pinning 绕过: 定向 hook LSE 内部 X509_verify_cert
    // hook_lse_writechain();  // 已禁用: 候选偏移非真实函数入口, MSHookFunction 打在函数中间 → 控制流损坏 → 栈溢出闪退
    hook_nw_connection_send();
    hook_nw_connection_create();
    if (!orig_SSL_CTX_set_verify) {
        void *fn = dlsym(RTLD_DEFAULT, "SSL_CTX_set_verify");
        if (fn) {
            MSHookFunction(fn, (void *)my_SSL_CTX_set_verify, (void **)&orig_SSL_CTX_set_verify);
            MBLogI(@"SSL-Pinning", @"成功挂钩 SSL_CTX_set_verify: %p", fn);
        }
    }
    if (!orig_SSL_get_verify_result) {
        if (orig_LSE_SSL_get_verify_result) {
            orig_SSL_get_verify_result = orig_LSE_SSL_get_verify_result;
            MBLogI(@"SSL-Pinning", @"⏭ 跳过全局 SSL_get_verify_result (已由 LSE 定向挂钩)");
        } else {
            void *fn = dlsym(RTLD_DEFAULT, "SSL_get_verify_result");
            if (fn) {
                MSHookFunction(fn, (void *)my_SSL_get_verify_result, (void **)&orig_SSL_get_verify_result);
                MBLogI(@"SSL-Pinning", @"成功挂钩 SSL_get_verify_result: %p", fn);
            }
        }
    }
    if (!orig_SSL_write) {
        // LSE 定向 SSL_write 已挂时禁止再 hook 同符号入口 (二次 MSHookFunction → trampoline 损坏闪退)
        if (orig_LSE_SSL_write) {
            orig_SSL_write = (SSL_write_ptr_t)orig_LSE_SSL_write;
            MBLogI(@"SSL-Pinning", @"⏭ 跳过全局 SSL_write (已由 LSE 定向挂钩)");
        } else {
            void *fn = dlsym(RTLD_DEFAULT, "SSL_write");
            if (fn) {
                MSHookFunction(fn, (void *)my_SSL_write, (void **)&orig_SSL_write);
                MBLogI(@"SSL-Pinning", @"成功挂钩 SSL_write 明文发送: %p", fn);
            }
        }
    }
    if (!orig_SSL_read) {
        if (orig_LSE_SSL_read) {
            orig_SSL_read = (SSL_read_ptr_t)orig_LSE_SSL_read;
            MBLogI(@"SSL-Pinning", @"⏭ 跳过全局 SSL_read (已由 LSE 定向挂钩)");
        } else {
            void *fn = dlsym(RTLD_DEFAULT, "SSL_read");
            if (fn) {
                MSHookFunction(fn, (void *)my_SSL_read, (void **)&orig_SSL_read);
                MBLogI(@"SSL-Pinning", @"成功挂钩 SSL_read 明文接收: %p", fn);
            }
        }
    }
    if (!orig_mbedtls_x509_crt_verify) {
        void *fn = dlsym(RTLD_DEFAULT, "mbedtls_x509_crt_verify");
        if (fn) {
            MSHookFunction(fn, (void *)my_mbedtls_x509_crt_verify, (void **)&orig_mbedtls_x509_crt_verify);
            MBLogI(@"SSL-Pinning", @"成功挂钩 mbedtls_x509_crt_verify: %p", fn);
        }
    }
    if (!orig_MBIGetCertificatePinning) {
        void *fn = dlsym(RTLD_DEFAULT, "MBIGetCertificatePinning");
        if (fn) {
            MSHookFunction(fn, (void *)my_MBIGetCertificatePinning, (void **)&orig_MBIGetCertificatePinning);
            MBLogI(@"SSL-Pinning", @"✅ 挂钩 MBIGetCertificatePinning (禁用 SPKI 固定): %p", fn);
        } else {
            MBLogW(@"SSL-Pinning", @"⚠️ 未找到 MBIGetCertificatePinning");
        }
    }
    if (!orig_MBIGetCertificatePinningFromBundles) {
        void *fn = dlsym(RTLD_DEFAULT, "MBIGetCertificatePinningFromBundles");
        if (fn) {
            MSHookFunction(fn, (void *)my_MBIGetCertificatePinningFromBundles, (void **)&orig_MBIGetCertificatePinningFromBundles);
            MBLogI(@"SSL-Pinning", @"✅ 挂钩 MBIGetCertificatePinningFromBundles: %p", fn);
        } else {
            MBLogW(@"SSL-Pinning", @"⚠️ 未找到 MBIGetCertificatePinningFromBundles");
        }
    }
    if (!orig_MBICertPinningHandleChallenge) {
        void *fn = dlsym(RTLD_DEFAULT, "MBICertPinningHandleChallenge");
        if (fn) {
            MSHookFunction(fn, (void *)my_MBICertPinningHandleChallenge, (void **)&orig_MBICertPinningHandleChallenge);
            MBLogI(@"SSL-Pinning", @"✅ 挂钩 MBICertPinningHandleChallenge (强制放行): %p", fn);
        } else {
            MBLogW(@"SSL-Pinning", @"⚠️ 未找到 MBICertPinningHandleChallenge");
        }
    }
    if (!orig_MNSSecureTCPConnectionEstablish) {
        void *fn = dlsym(RTLD_DEFAULT, MNS_SYM_SECURETCP_ESTABLISH);
        if (fn) {
            MSHookFunction(fn, (void *)my_MNSSecureTCPConnectionEstablish, (void **)&orig_MNSSecureTCPConnectionEstablish);
            MBLogI(@"SSL-Pinning", @"✅ 挂钩 MNSSecureTCPConnectionEstablish (MNS/TCP host:port): %p", fn);
        } else {
            MBLogW(@"SSL-Pinning", @"⚠️ 未找到 MNSSecureTCPConnectionEstablish (LightSpeedEngine 未加载?)");
        }
    }
    if (!orig_MNSTCPConnectionEstablish) {
        void *fn = dlsym(RTLD_DEFAULT, MNS_SYM_TCP_ESTABLISH);
        if (fn) {
            MSHookFunction(fn, (void *)my_MNSTCPConnectionEstablish, (void **)&orig_MNSTCPConnectionEstablish);
            MBLogI(@"SSL-Pinning", @"✅ 挂钩 MNSTCPConnectionEstablish: %p", fn);
        }
    }
    if (!orig_MNSHTTPClientCreateWithSettings) {
        void *fn = dlsym(RTLD_DEFAULT, MNS_SYM_HTTPCLIENT_CREATE);
        if (fn) {
            MSHookFunction(fn, (void *)my_MNSHTTPClientCreateWithSettings, (void **)&orig_MNSHTTPClientCreateWithSettings);
            MBLogI(@"SSL-Pinning", @"✅ 挂钩 MNSHTTPClientCreateWithSettings (MNS endpoint URL): %p", fn);
        } else {
            static int once_http_create = 0;
            if (!once_http_create++) {
                MBLogW(@"SSL-Pinning", @"⚠️ 未找到 MNSHTTPClientCreateWithSettings (仅记一次)");
            }
        }
    }
    if (!orig_MNSHTTPClientSendRequest) {
        void *fn = dlsym(RTLD_DEFAULT, MNS_SYM_HTTPCLIENT_SEND);
        if (fn) {
            MSHookFunction(fn, (void *)my_MNSHTTPClientSendRequest, (void **)&orig_MNSHTTPClientSendRequest);
            MBLogI(@"SSL-Pinning", @"✅ 挂钩 MNSHTTPClientSendRequest (MNS 发送路径): %p", fn);
        } else {
            static int once_http_send = 0;
            if (!once_http_send++) {
                MBLogW(@"SSL-Pinning", @"⚠️ 未找到 MNSHTTPClientSendRequest (仅记一次)");
            }
        }
    }
    if (!orig_MNSSecureTCPConnectionSend) {
        void *fn = dlsym(RTLD_DEFAULT, "MNSSecureTCPConnectionSend");
        if (fn) {
            MSHookFunction(fn, (void *)my_MNSSecureTCPConnectionSend, (void **)&orig_MNSSecureTCPConnectionSend);
            MBLogI(@"SSL-Pinning", @"✅ 挂钩 MNSSecureTCPConnectionSend (MNS 明文帧): %p", fn);
        } else {
            MBLogW(@"SSL-Pinning", @"⚠️ 未找到 MNSSecureTCPConnectionSend");
        }
    }
    if (!orig_MNSTCPConnectionSend) {
        void *fn = dlsym(RTLD_DEFAULT, "MNSTCPConnectionSend");
        if (fn) {
            MSHookFunction(fn, (void *)my_MNSTCPConnectionSend, (void **)&orig_MNSTCPConnectionSend);
            MBLogI(@"SSL-Pinning", @"✅ 挂钩 MNSTCPConnectionSend: %p", fn);
        } else {
            MBLogW(@"SSL-Pinning", @"⚠️ 未找到 MNSTCPConnectionSend");
        }
    }
    // [已禁用] getALPNProtocol hook:
    // 调用约定/返回值并非稳定 MCFString*, 在 DB 打开线程触发 objc_retain(0x1) -> EXC_BAD_ACCESS,
    // 导致 Messenger 启动即崩、gateway 建连抓不到。ALPN 改由 VPN ClientHello / Java 侧观测。
    // if (!orig_getALPNProtocol) { ... }

    if (!orig_X509_verify_cert) {
        if (orig_LSE_X509_verify_cert) {
            orig_X509_verify_cert = orig_LSE_X509_verify_cert;
            MBLogI(@"SSL-Pinning", @"⏭ 跳过全局 X509_verify_cert (已由 LSE 定向挂钩)");
        } else {
            void *fn = dlsym(RTLD_DEFAULT, "X509_verify_cert");
            if (fn) {
                MSHookFunction(fn, (void *)my_X509_verify_cert, (void **)&orig_X509_verify_cert);
                MBLogI(@"SSL-Pinning", @"成功挂钩 X509_verify_cert: %p", fn);
            }
        }
    }
    if (!orig_SSL_get_verify_result) {
        if (orig_LSE_SSL_get_verify_result) {
            orig_SSL_get_verify_result = orig_LSE_SSL_get_verify_result;
            MBLogI(@"SSL-Pinning", @"⏭ 跳过全局 SSL_get_verify_result (已由 LSE 定向挂钩)");
        } else {
            void *fn = dlsym(RTLD_DEFAULT, "SSL_get_verify_result");
            if (fn) {
                MSHookFunction(fn, (void *)my_SSL_get_verify_result, (void **)&orig_SSL_get_verify_result);
                MBLogI(@"SSL-Pinning", @"成功挂钩 SSL_get_verify_result: %p", fn);
            }
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
// 8. E2EE 端到端加密消息与 DGW / MNS 深度监控模块 (E2EE & DGW/MNS Deep Monitor)
// ============================================================================

#import <sqlite3.h>

// ----------------------------------------------------------------------------
// 8.1 SQLite 核心数据落库与执行监控
// ----------------------------------------------------------------------------
typedef int (*sqlite3_prepare_v2_ptr_t)(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
static sqlite3_prepare_v2_ptr_t orig_sqlite3_prepare_v2 = NULL;

typedef int (*sqlite3_step_ptr_t)(sqlite3_stmt *pStmt);
static sqlite3_step_ptr_t orig_sqlite3_step = NULL;

typedef int (*sqlite3_bind_blob_ptr_t)(sqlite3_stmt *stmt, int index, const void *val, int n, void(*destructor)(void*));
static sqlite3_bind_blob_ptr_t orig_sqlite3_bind_blob = NULL;

typedef int (*sqlite3_bind_text_ptr_t)(sqlite3_stmt *stmt, int index, const char *val, int n, void(*destructor)(void*));
static sqlite3_bind_text_ptr_t orig_sqlite3_bind_text = NULL;

static int my_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail) {
    if (zSql) {
        NSString *sqlStr = [NSString stringWithUTF8String:zSql];
        if ([sqlStr containsString:@"send_status"] || [sqlStr containsString:@"client_messages"] || 
            [sqlStr containsString:@"advanced_crypto_transport_messages"] || [sqlStr containsString:@"secure_message_session_state_v2"] ||
            [sqlStr containsString:@"tam_remora_send"] || [sqlStr containsString:@"pending_tasks"]) {
            MBLogI(@"SQL_E2EE", @"💾 [SQLite prepare] SQL: %@", sqlStr);
        }
        // 结论#3 验证: 真机 E2EE 发送/入库路径写入 franking 签名 (Java 侧完全缺失)
        if ([sqlStr containsString:@"franking"] || [sqlStr containsString:@"reporting_tag"]) {
            MBLogI(@"E2EE-VERIFY", @"[结论#3][Franking] 真机执行含 franking 字段的 SQL (证明存在 franking 机制): %@",
                   sqlStr.length > 400 ? [sqlStr substringToIndex:400] : sqlStr);
        }
    }
    return orig_sqlite3_prepare_v2 ? orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail) : SQLITE_ERROR;
}

// ---- 端到端注入 v2: 提前到 franking/ACT/文本, 并覆盖自身+对端信封 ----
// 上次只改 session_cipher_encrypt 入参失败: ACT/franking 已按原文绑定, 发出去仍是原文。
// 现改为 armed 窗口内一致替换: bind_text(正文) + bind_blob(ACT) + encrypt(自身/对端信封)。
#ifndef SQLITE_TRANSIENT
#define SQLITE_TRANSIENT ((void(*)(void *))-1)
#endif

static NSString *mb_doc_file(NSString *name) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *base = paths.firstObject;
    return base ? [base stringByAppendingPathComponent:name] : nil;
}

static uint8_t *g_inj_text = NULL; size_t g_inj_text_len = 0;
static uint8_t *g_inj_act = NULL; size_t g_inj_act_len = 0;
static uint8_t *g_inj_env = NULL; size_t g_inj_env_len = 0;
static uint8_t *g_inj_env_self = NULL; size_t g_inj_env_self_len = 0;
static NSTimeInterval g_inj_loaded_at = 0;

static uint8_t *mb_load_bin(NSString *name, size_t *outLen) {
    NSString *path = mb_doc_file(name);
    if (!path) return NULL;
    NSData *d = [NSData dataWithContentsOfFile:path];
    if (!d || d.length == 0) return NULL;
    uint8_t *p = (uint8_t *)malloc(d.length);
    if (!p) return NULL;
    memcpy(p, d.bytes, d.length);
    *outLen = d.length;
    return p;
}

static void mb_reload_inject_artifacts(void) {
    free(g_inj_text); g_inj_text = NULL; g_inj_text_len = 0;
    free(g_inj_act); g_inj_act = NULL; g_inj_act_len = 0;
    free(g_inj_env); g_inj_env = NULL; g_inj_env_len = 0;
    free(g_inj_env_self); g_inj_env_self = NULL; g_inj_env_self_len = 0;
    g_inj_text = mb_load_bin(@"mb_inject_text.txt", &g_inj_text_len);
    g_inj_act = mb_load_bin(@"mb_inject_act.bin", &g_inj_act_len);
    g_inj_env = mb_load_bin(@"mb_inject_env.bin", &g_inj_env_len);
    g_inj_env_self = mb_load_bin(@"mb_inject_env_self.bin", &g_inj_env_self_len);
    g_inj_loaded_at = [NSDate date].timeIntervalSince1970;
    MBLogI(@"INJECT", @"📦 加载注入物料 text=%zu act=%zu env=%zu env_self=%zu",
           g_inj_text_len, g_inj_act_len, g_inj_env_len, g_inj_env_self_len);
}

/** armed = Documents/mb_inject_arm 存在且 40s 内。
 *  明文注入已验证通过 (对方收到 JAVA-E2EE-*), 默认关闭; 置 mb_inject_plain=1 才重新启用。 */
static BOOL mb_inject_armed(void) {
    @try {
        NSString *plainFlag = mb_doc_file(@"mb_inject_plain");
        if (!plainFlag || ![[NSFileManager defaultManager] fileExistsAtPath:plainFlag]) {
            return NO; // 明文注入已放开/关闭
        }
        NSString *armPath = mb_doc_file(@"mb_inject_arm");
        if (!armPath) return NO;
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:armPath]) return NO;
        NSDictionary *attr = [fm attributesOfItemAtPath:armPath error:nil];
        NSDate *mt = attr[NSFileModificationDate];
        if (mt && [[NSDate date] timeIntervalSinceDate:mt] > 40.0) return NO;
        // arm 后首次或物料过旧则重载 (保证与本次推送的 bin 一致)
        if (!g_inj_env || !g_inj_act || !g_inj_text ||
            (mt && mt.timeIntervalSince1970 > g_inj_loaded_at)) {
            mb_reload_inject_artifacts();
        }
        return (g_inj_text_len > 0 && g_inj_act_len > 0 && g_inj_env_len > 0 && g_inj_env_self_len > 0);
    } @catch (__unused NSException *e) { return NO; }
}

static BOOL mb_looks_like_msg_text(const char *val, int n) {
    if (!val || n <= 0 || n > 80) return NO;
    if (strstr(val, "client_") || strstr(val, "facebook") || strstr(val, "FBLegacy") ||
        strstr(val, "AdvancedCrypto") || strstr(val, "tam_remora") || strstr(val, "UFS-") ||
        strchr(val, '^') || strstr(val, "@msgr") || strstr(val, "encrypt_result") ||
        strstr(val, "send_task") || strstr(val, "deviceJID") || strstr(val, "cursor") ||
        strstr(val, "qpl_") || strstr(val, "server_epoch") || strstr(val, "db_type") ||
        strcmp(val, "null") == 0 || strcmp(val, "NONE") == 0 || strcmp(val, "none") == 0)
        return NO;
    // UUID
    int hy = 0; for (int i = 0; i < n; i++) if (val[i] == '-') hy++;
    if (hy >= 4 && n >= 36) return NO;
    // 纯长数字 (OTID/UID)
    int digits = 0; for (int i = 0; i < n; i++) if (val[i] >= '0' && val[i] <= '9') digits++;
    if (digits == n && n >= 10) return NO;
    // base64-ish tokens
    if (n >= 20 && digits < n / 4) {
        int b64 = 0;
        for (int i = 0; i < n; i++) {
            char c = val[i];
            if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='='||c=='_'||c=='-') b64++;
        }
        if (b64 == n) return NO;
    }
    // 至少有一个字母或非 ascii 可读正文
    int letters = 0;
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)val[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c >= 0x80) letters++;
    }
    return letters > 0;
}

static BOOL mb_blob_has_msgr(const uint8_t *b, int n) {
    for (int i = 0; i + 5 <= n; i++)
        if (b[i] == '@' && memcmp(b + i, "@msgr", 5) == 0) return YES;
    return NO;
}

/** ACT 明文: 小 protobuf, 以 0x0a 开头, 无 @msgr, 尺寸接近 franking 绑定对象。 */
static BOOL mb_looks_like_act_blob(const uint8_t *b, int n) {
    if (!b || n < 40 || n > 120) return NO;
    if (b[0] != 0x0a) return NO;
    if (mb_blob_has_msgr(b, n)) return NO;
    // 排除 zlib (78 da) / 大密文包装
    if (n >= 2 && b[0] == 0x78) return NO;
    return YES;
}

static int my_sqlite3_bind_blob(sqlite3_stmt *stmt, int index, const void *val, int n, void(*destructor)(void*)) {
    const void *use = val; int useN = n; void(*useDest)(void*) = destructor;
    @try {
        if (val && n > 0 && mb_inject_armed() && mb_looks_like_act_blob((const uint8_t *)val, n) && g_inj_act) {
            use = g_inj_act; useN = (int)g_inj_act_len; useDest = SQLITE_TRANSIENT;
            MBLogI(@"INJECT", @"💉 [ACT-BLOB] idx=%d 原文%d字节 -> Java ACT %d字节 (franking 前替换)",
                   index, n, useN);
        }
    } @catch (__unused NSException *e) {}
    if (use && useN > 0) {
        const uint8_t *b = (const uint8_t *)use;
        if (useN >= 16 && (b[0] == 0x0a || b[0] == 0x02 || b[0] == 0x03 || useN == 32 || useN > 100)) {
            MBLogI(@"E2EE_SQL_BLOB", @"🔑 [SQLite Bind BLOB] 索引: %d | 长度: %d 字节 | Hex: %@",
                   index, useN, mb_hex_dump(use, useN, 256));
        }
    }
    return orig_sqlite3_bind_blob ? orig_sqlite3_bind_blob(stmt, index, use, useN, useDest) : SQLITE_ERROR;
}

static int my_sqlite3_bind_text(sqlite3_stmt *stmt, int index, const char *val, int n, void(*destructor)(void*)) {
    const char *use = val; int useN = n; void(*useDest)(void*) = destructor;
    @try {
        int realN = n;
        if (realN < 0 && val) realN = (int)strlen(val);
        if (val && realN > 0 && mb_inject_armed() && g_inj_text && mb_looks_like_msg_text(val, realN)) {
            // 预览串 "前缀: 原文" → 保留前缀换正文
            const char *colon = strrchr(val, ':');
            if (colon && (colon - val) < realN - 1 && (colon - val) <= 12) {
                // 构造 "前缀: JAVA_TEXT"
                static char previewBuf[160];
                size_t prefixLen = (size_t)(colon - val + 2); // 含 ": "
                if (prefixLen + g_inj_text_len < sizeof(previewBuf)) {
                    memcpy(previewBuf, val, prefixLen);
                    memcpy(previewBuf + prefixLen, g_inj_text, g_inj_text_len);
                    previewBuf[prefixLen + g_inj_text_len] = 0;
                    use = previewBuf; useN = (int)(prefixLen + g_inj_text_len); useDest = SQLITE_TRANSIENT;
                    MBLogI(@"INJECT", @"💉 [TEXT-PREVIEW] idx=%d \"%.*s\" -> \"%s\"", index, realN, val, previewBuf);
                }
            } else {
                use = (const char *)g_inj_text; useN = (int)g_inj_text_len; useDest = SQLITE_TRANSIENT;
                MBLogI(@"INJECT", @"💉 [TEXT] idx=%d \"%.*s\" -> \"%.*s\"", index, realN, val, useN, use);
            }
        }
    } @catch (__unused NSException *e) {}
    if (use && ((useN > 0) || (useN < 0 && strlen(use) > 0))) {
        MBLogI(@"E2EE_SQL_TEXT", @"📝 [SQLite Bind TEXT] 索引: %d | 内容: %s", index, use);
    }
    return orig_sqlite3_bind_text ? orig_sqlite3_bind_text(stmt, index, use, useN, useDest) : SQLITE_ERROR;
}

// ----------------------------------------------------------------------------
// 8.2 Signal Protocol C API 加解密与棘轮步进监控
// ----------------------------------------------------------------------------
typedef struct signal_buffer signal_buffer;
typedef struct ciphertext_message ciphertext_message;

typedef int (*session_cipher_encrypt_ptr_t)(void *cipher, const uint8_t *padded_message, size_t padded_message_len, void **encrypted_message);
static session_cipher_encrypt_ptr_t orig_session_cipher_encrypt = NULL;

/** 返回应注入的信封 (malloc 缓冲, 生命周期跨 encrypt 调用)。recipient=@msgr 用 env, 否则用 env_self。 */
static BOOL mb_pick_inject_env(const uint8_t *pm, size_t len, const uint8_t **out, size_t *outLen) {
    if (!mb_inject_armed() || !pm || len < 20) return NO;
    // Armadillo 信封以 0x0a 开头
    if (pm[0] != 0x0a) return NO;
    BOOL isRecipient = mb_blob_has_msgr(pm, (int)len);
    if (isRecipient) {
        if (!g_inj_env || g_inj_env_len == 0) return NO;
        *out = g_inj_env; *outLen = g_inj_env_len;
        return YES;
    }
    // 自身副本: 尺寸通常 90-140, 无 JID
    if (len >= 80 && len <= 200) {
        if (!g_inj_env_self || g_inj_env_self_len == 0) return NO;
        *out = g_inj_env_self; *outLen = g_inj_env_self_len;
        return YES;
    }
    return NO;
}

// ---- 密文注入: 按 uid:deviceId 替换 session_cipher_encrypt 输出 ----
typedef struct {
    char key[64]; // "uid:deviceId"
    int type;
    uint8_t *data;
    size_t len;
} mb_ct_entry_t;

static mb_ct_entry_t *g_ct_entries = NULL;
static int g_ct_count = 0;
static NSTimeInterval g_ct_loaded_at = 0;

static void mb_free_ct_map(void) {
    if (!g_ct_entries) return;
    for (int i = 0; i < g_ct_count; i++) free(g_ct_entries[i].data);
    free(g_ct_entries); g_ct_entries = NULL; g_ct_count = 0;
}

static int mb_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void mb_reload_ct_map(void) {
    mb_free_ct_map();
    NSString *path = mb_doc_file(@"mb_inject_ct_map.txt");
    if (!path) return;
    NSString *content = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (!content.length) return;
    NSArray *lines = [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    mb_ct_entry_t *arr = (mb_ct_entry_t *)calloc(lines.count, sizeof(mb_ct_entry_t));
    int n = 0;
    for (NSString *line in lines) {
        if (line.length < 8) continue;
        // uid:dev:type:hex  — uid 与 dev 用第一个和第二个 ':', type 第三个
        NSArray *parts = [line componentsSeparatedByString:@":"];
        if (parts.count < 4) continue;
        NSString *uid = parts[0];
        NSString *dev = parts[1];
        int typ = [parts[2] intValue];
        NSString *hex = [[parts subarrayWithRange:NSMakeRange(3, parts.count - 3)] componentsJoinedByString:@":"];
        // hex 不应含 ':', join 无害
        hex = parts[3];
        if (hex.length % 2) continue;
        size_t blen = hex.length / 2;
        uint8_t *buf = (uint8_t *)malloc(blen);
        if (!buf) continue;
        BOOL ok = YES;
        for (size_t i = 0; i < blen; i++) {
            int hi = mb_hex_nibble([hex characterAtIndex:i * 2]);
            int lo = mb_hex_nibble([hex characterAtIndex:i * 2 + 1]);
            if (hi < 0 || lo < 0) { ok = NO; break; }
            buf[i] = (uint8_t)((hi << 4) | lo);
        }
        if (!ok) { free(buf); continue; }
        snprintf(arr[n].key, sizeof(arr[n].key), "%s:%s", uid.UTF8String, dev.UTF8String);
        arr[n].type = typ;
        arr[n].data = buf;
        arr[n].len = blen;
        n++;
    }
    g_ct_entries = arr;
    g_ct_count = n;
    g_ct_loaded_at = [NSDate date].timeIntervalSince1970;
    MBLogI(@"INJECT", @"📦 加载密文 map %d 条", g_ct_count);
}

static BOOL mb_cipher_inject_armed(void) {
    @try {
        NSString *flag = mb_doc_file(@"mb_inject_cipher");
        NSString *arm = mb_doc_file(@"mb_inject_arm");
        if (!flag || !arm) return NO;
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:flag] || ![fm fileExistsAtPath:arm]) return NO;
        NSDictionary *attr = [fm attributesOfItemAtPath:arm error:nil];
        NSDate *mt = attr[NSFileModificationDate];
        if (mt && [[NSDate date] timeIntervalSinceDate:mt] > 40.0) return NO;
        if (!g_ct_entries || (mt && mt.timeIntervalSince1970 > g_ct_loaded_at)) {
            mb_reload_ct_map();
        }
        return g_ct_count > 0;
    } @catch (__unused NSException *e) { return NO; }
}

typedef struct {
    const char *name;
    size_t name_len;
    uint32_t device_id;
} mb_signal_address_t;

/** 从 session_cipher* 猜测 remote_address (libsignal: store @0, address @1)。 */
static BOOL mb_cipher_read_address(void *cipher, char *uidOut, size_t uidCap, uint32_t *devOut) {
    if (!cipher || !uidOut || !devOut) return NO;
    @try {
        void **slots = (void **)cipher;
        // 尝试 offset 1 与 2 (Meta 可能微调布局)
        for (int idx = 1; idx <= 3; idx++) {
            mb_signal_address_t *addr = (mb_signal_address_t *)slots[idx];
            if (!addr) continue;
            // name 指针应可读且为数字串
            const char *name = addr->name;
            if (!name) continue;
            size_t nlen = addr->name_len;
            if (nlen < 5 || nlen > 20) nlen = strnlen(name, 24);
            if (nlen < 5 || nlen > 20) continue;
            BOOL allDigit = YES;
            for (size_t i = 0; i < nlen; i++) {
                if (name[i] < '0' || name[i] > '9') { allDigit = NO; break; }
            }
            if (!allDigit) continue;
            uint32_t did = addr->device_id;
            if (did == 0 || did > 256) continue;
            if (nlen >= uidCap) continue;
            memcpy(uidOut, name, nlen); uidOut[nlen] = 0;
            *devOut = did;
            return YES;
        }
    } @catch (__unused NSException *e) {}
    return NO;
}

static mb_ct_entry_t *mb_ct_find(const char *uid, uint32_t dev) {
    char key[64];
    snprintf(key, sizeof(key), "%s:%u", uid, dev);
    for (int i = 0; i < g_ct_count; i++) {
        if (strcmp(g_ct_entries[i].key, key) == 0) return &g_ct_entries[i];
    }
    return NULL;
}

typedef int (*signal_message_deserialize_t)(void **message, const uint8_t *data, size_t len, void *global_context);
typedef int (*prekey_deserialize_t)(void **message, const uint8_t *data, size_t len, void *global_context);
typedef void (*signal_type_unref_t)(void *instance);
static signal_message_deserialize_t g_signal_msg_des = NULL;
static prekey_deserialize_t g_prekey_des = NULL;
static signal_type_unref_t g_signal_unref = NULL;

static void mb_init_signal_ct_apis(void) {
    if (g_signal_msg_des) return;
    g_signal_msg_des = (signal_message_deserialize_t)dlsym(RTLD_DEFAULT, "signal_message_deserialize");
    g_prekey_des = (prekey_deserialize_t)dlsym(RTLD_DEFAULT, "pre_key_signal_message_deserialize");
    g_signal_unref = (signal_type_unref_t)dlsym(RTLD_DEFAULT, "signal_type_unref");
}

/** 尝试从 session_cipher 取 signal_context* (常见布局 store/address/context)。 */
static void *mb_cipher_get_context(void *cipher) {
    if (!cipher) return NULL;
    void **slots = (void **)cipher;
    // 优先尝试 index 2
    for (int idx = 2; idx <= 4; idx++) {
        if (slots[idx]) return slots[idx];
    }
    return NULL;
}

typedef int (*session_cipher_decrypt_signal_message_ptr_t)(void *cipher, void *ciphertext, void **plaintext);
static session_cipher_decrypt_signal_message_ptr_t orig_session_cipher_decrypt_signal_message = NULL;

static int my_session_cipher_encrypt(void *cipher, const uint8_t *padded_message, size_t padded_message_len, void **encrypted_message) {
    @try {
        if (padded_message && padded_message_len > 0) {
            MBLogI(@"SIGNAL_CIPHER", @"🔐 [Signal Encrypt 输入明文] 长度: %zu 字节 | Hex: %@",
                   padded_message_len, mb_hex_dump(padded_message, padded_message_len, 512));
            // 结论#2 验证: 解析真机加密明文的 protobuf 顶层结构, 与 Java 单层 135B 自造信封对比
            NSString *proto = mb_parse_protobuf_top_level(padded_message, padded_message_len);
            MBLogI(@"E2EE-VERIFY", @"[结论#2][信封结构] 真机 Signal 加密明文顶层字段布局 (总长 %zu 字节): %@",
                   padded_message_len, proto);
        }
    } @catch (__unused NSException *ex) {}
    // 端到端注入 v2: 按 session 对端 uid 选自身/对端信封 (不再靠原文是否含 @msgr)
    const uint8_t *pm_use = padded_message; size_t pml_use = padded_message_len;
    @try {
        if (mb_inject_armed()) {
            char uid[32] = {0}; uint32_t dev = 0;
            BOOL gotAddr = mb_cipher_read_address(cipher, uid, sizeof(uid), &dev);
            const uint8_t *inj = NULL; size_t injLen = 0;
            if (gotAddr && g_inj_env && g_inj_env_self) {
                // 对端 uid → recipient 信封; 自身 uid → self 信封
                BOOL isSelf = (strncmp(uid, "100007411578573", 15) == 0);
                inj = isSelf ? g_inj_env_self : g_inj_env;
                injLen = isSelf ? g_inj_env_self_len : g_inj_env_len;
                MBLogI(@"INJECT", @"💉 [ENCRYPT-%s] %s:%u 原文 %zu -> Java 信封 %zu",
                       isSelf ? "自身" : "对端", uid, dev, padded_message_len, injLen);
            } else if (mb_pick_inject_env(padded_message, padded_message_len, &inj, &injLen)) {
                MBLogI(@"INJECT", @"💉 [ENCRYPT-fallback] 原文 %zu -> Java 信封 %zu",
                       padded_message_len, injLen);
            }
            if (inj && injLen > 0) { pm_use = inj; pml_use = injLen; }
        }
    } @catch (__unused NSException *ex) {}
    int res = orig_session_cipher_encrypt ? orig_session_cipher_encrypt(cipher, pm_use, pml_use, encrypted_message) : -1;
    // 密文注入: 官方加密推进本地棘轮后, 用 Java 预计算密文替换输出 (会话状态取自加密前 dump)
    @try {
        if (res == 0 && encrypted_message && *encrypted_message && mb_cipher_inject_armed()) {
            mb_init_signal_ct_apis();
            char uid[32] = {0}; uint32_t dev = 0;
            if (mb_cipher_read_address(cipher, uid, sizeof(uid), &dev)) {
                mb_ct_entry_t *ent = mb_ct_find(uid, dev);
                if (ent && g_signal_msg_des && g_prekey_des) {
                    void *ctx = mb_cipher_get_context(cipher);
                    void *neu = NULL;
                    int dr = -1;
                    if (ent->type == 3) // PREKEY
                        dr = g_prekey_des(&neu, ent->data, ent->len, ctx);
                    else
                        dr = g_signal_msg_des(&neu, ent->data, ent->len, ctx);
                    if (dr == 0 && neu) {
                        void *old = *encrypted_message;
                        *encrypted_message = neu;
                        if (g_signal_unref && old) g_signal_unref(old);
                        MBLogI(@"INJECT", @"💉 [CIPHER] %s:%u 替换为 Java 密文 %zu 字节 type=%d",
                               uid, dev, ent->len, ent->type);
                    } else {
                        // fallback: 若长度相同则就地覆盖 serialized buffer
                        void *(*p_get_buf)(void *) = (void *(*)(void *))dlsym(RTLD_DEFAULT, "ciphertext_message_get_serialized");
                        uint8_t *(*p_buf_data)(void *) = (uint8_t *(*)(void *))dlsym(RTLD_DEFAULT, "signal_buffer_data");
                        size_t (*p_buf_len)(void *) = (size_t (*)(void *))dlsym(RTLD_DEFAULT, "signal_buffer_len");
                        BOOL replaced = NO;
                        if (p_get_buf && p_buf_data && p_buf_len) {
                            void *buf = p_get_buf(*encrypted_message);
                            if (buf && p_buf_len(buf) == ent->len) {
                                memcpy(p_buf_data(buf), ent->data, ent->len);
                                replaced = YES;
                                MBLogI(@"INJECT", @"💉 [CIPHER-MEMCPY] %s:%u 就地覆盖 %zu 字节", uid, dev, ent->len);
                            }
                        }
                        if (!replaced) {
                            MBLogW(@"INJECT", @"⚠️ [CIPHER] deserialize 失败 uid=%s dev=%u type=%d dr=%d ctx=%p",
                                   uid, dev, ent->type, dr, ctx);
                        }
                    }
                } else {
                    MBLogI(@"INJECT", @"ℹ️ [CIPHER] 无 Java 密文 %s:%u (跳过)", uid, dev);
                }
            } else {
                MBLogW(@"INJECT", @"⚠️ [CIPHER] 无法从 session_cipher 读取 address");
            }
        }
    } @catch (__unused NSException *ex) {}
    @try {
        if (res == 0 && encrypted_message && *encrypted_message) {
            void *(*p_get_buf)(void *) = (void *(*)(void *))dlsym(RTLD_DEFAULT, "ciphertext_message_get_serialized") ?: (void *(*)(void *))dlsym(RTLD_DEFAULT, "_ciphertext_message_get_serialized");
            uint8_t *(*p_buf_data)(void *) = (uint8_t *(*)(void *))dlsym(RTLD_DEFAULT, "signal_buffer_data") ?: (uint8_t *(*)(void *))dlsym(RTLD_DEFAULT, "_signal_buffer_data");
            size_t (*p_buf_len)(void *) = (size_t (*)(void *))dlsym(RTLD_DEFAULT, "signal_buffer_len") ?: (size_t (*)(void *))dlsym(RTLD_DEFAULT, "_signal_buffer_len");
            if (p_get_buf && p_buf_data && p_buf_len) {
                void *buf = p_get_buf(*encrypted_message);
                if (buf) {
                    uint8_t *cdata = p_buf_data(buf);
                    size_t clen = p_buf_len(buf);
                    MBLogI(@"SIGNAL_CIPHER", @"🔑 [Signal Encrypt 输出密文] 长度: %zu 字节 | Hex: %@",
                           clen, mb_hex_dump(cdata, clen, 256));
                    // 结论#1 验证: 记录密文指纹, 供出站 TLS/socket 帧定位真实 DGW 封装
                    mb_remember_cipher(cdata, clen);
                }
            }
        }
    } @catch (__unused NSException *ex) {}
    return res;
}

static int my_session_cipher_decrypt_signal_message(void *cipher, void *ciphertext, void **plaintext) {
    int res = orig_session_cipher_decrypt_signal_message ? orig_session_cipher_decrypt_signal_message(cipher, ciphertext, plaintext) : -1;
    @try {
        if (res == 0 && plaintext && *plaintext) {
            uint8_t *(*p_buf_data)(void *) = (uint8_t *(*)(void *))dlsym(RTLD_DEFAULT, "signal_buffer_data") ?: (uint8_t *(*)(void *))dlsym(RTLD_DEFAULT, "_signal_buffer_data");
            size_t (*p_buf_len)(void *) = (size_t (*)(void *))dlsym(RTLD_DEFAULT, "signal_buffer_len") ?: (size_t (*)(void *))dlsym(RTLD_DEFAULT, "_signal_buffer_len");
            if (p_buf_data && p_buf_len) {
                uint8_t *pdata = p_buf_data(*plaintext);
                size_t plen = p_buf_len(*plaintext);
                MBLogI(@"SIGNAL_CIPHER", @"🔓 [Signal Decrypt 接收解密] 长度: %zu 字节 | Hex: %@",
                       plen, mb_hex_dump(pdata, plen, 256));
            }
        }
    } @catch (__unused NSException *ex) {}
    return res;
}

// ----------------------------------------------------------------------------
// 8.2.1 结论#5 验证: libsignal C API 家族 (与 Java whispersystems 同源) + PreKey/群聊 sender_key
// ----------------------------------------------------------------------------
// PreKey 消息解密 (入站首帧 X3DH), 证明真机与 Java 使用同一 libsignal-protocol-C API
typedef int (*session_cipher_decrypt_pre_key_ptr_t)(void *cipher, void *ciphertext, void **plaintext);
static session_cipher_decrypt_pre_key_ptr_t orig_session_cipher_decrypt_pre_key = NULL;
static int my_session_cipher_decrypt_pre_key(void *cipher, void *ciphertext, void **plaintext) {
    MBLogI(@"E2EE-VERIFY", @"[结论#5][libsignal] 命中 session_cipher_decrypt_pre_key_signal_message —— 真机使用 libsignal-protocol-C (与 Java whispersystems 同源)");
    return orig_session_cipher_decrypt_pre_key ? orig_session_cipher_decrypt_pre_key(cipher, ciphertext, plaintext) : -1;
}

// X3DH 会话建立: process_pre_key_bundle. bundle 来源于服务端在线下发的设备公钥 (呼应结论#4)
typedef int (*session_builder_process_pre_key_bundle_ptr_t)(void *builder, const void *bundle);
static session_builder_process_pre_key_bundle_ptr_t orig_session_builder_process_pre_key_bundle = NULL;
static int my_session_builder_process_pre_key_bundle(void *builder, const void *bundle) {
    MBLogI(@"E2EE-VERIFY", @"[结论#4/#5][X3DH] 命中 session_builder_process_pre_key_bundle —— 真机用在线获取的 PreKeyBundle 动态建立会话 (Java 靠预导入 iPhone 会话)");
    return orig_session_builder_process_pre_key_bundle ? orig_session_builder_process_pre_key_bundle(builder, bundle) : -1;
}

// 群聊 sender_key store 注册, 证明真机支持群聊 sender_key 分发 (Java 侧完全缺失)
typedef int (*set_sender_key_store_ptr_t)(void *ctx, const void *store);
static set_sender_key_store_ptr_t orig_set_sender_key_store = NULL;
static int my_set_sender_key_store(void *ctx, const void *store) {
    MBLogI(@"E2EE-VERIFY", @"[结论#5][群聊] 命中 signal_protocol_store_context_set_sender_key_store —— 真机注册群聊 sender_key 存储 (Java 仅实现 1:1 pairwise, 无 sender_key)");
    return orig_set_sender_key_store ? orig_set_sender_key_store(ctx, store) : -1;
}

// ----------------------------------------------------------------------------
// 8.3 DGW / MNS 底层 Socket 流量抓取 (443端口 IPv4 & IPv6)
// ----------------------------------------------------------------------------
typedef ssize_t (*send_ptr_t)(int socket, const void *buffer, size_t length, int flags);
static send_ptr_t orig_send = NULL;

typedef ssize_t (*recv_ptr_t)(int socket, void *buffer, size_t length, int flags);
static recv_ptr_t orig_recv = NULL;

typedef ssize_t (*write_ptr_t)(int fildes, const void *buf, size_t nbyte);
static write_ptr_t orig_write = NULL;

typedef ssize_t (*read_ptr_t)(int fildes, void *buf, size_t nbyte);
static read_ptr_t orig_read = NULL;

static BOOL is_ssl_socket(int sockfd) {
    struct sockaddr_storage peer;
    socklen_t len = sizeof(peer);
    if (getpeername(sockfd, (struct sockaddr *)&peer, &len) == 0) {
        if (peer.ss_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)&peer;
            if (ntohs(in->sin_port) == 443) return YES;
        } else if (peer.ss_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&peer;
            if (ntohs(in6->sin6_port) == 443) return YES;
        }
    }
    return NO;
}

static ssize_t my_send(int socket, const void *buffer, size_t length, int flags) {
    if (buffer && length > 0 && is_ssl_socket(socket)) {
        if (mb_mns_capture_armed()) {
            mb_dump_first_frame("DGW_send", (void *)(uintptr_t)socket, buffer, length);
        } else {
            MBLogI(@"DGW_MNS_TX", @"🚀 [MNS Socket TX(send)] 大小: %zu 字节 | 前部 Hex: %@",
                   length, mb_hex_dump(buffer, length, 128));
        }
        if (length > 16) mb_analyze_outbound_frame("send", (const uint8_t *)buffer, length);
    }
    return orig_send ? orig_send(socket, buffer, length, flags) : -1;
}

static ssize_t my_recv(int socket, void *buffer, size_t length, int flags) {
    ssize_t res = orig_recv ? orig_recv(socket, buffer, length, flags) : -1;
    if (res > 0 && buffer && is_ssl_socket(socket)) {
        MBLogI(@"DGW_MNS_RX", @"📥 [MNS Socket RX(recv)] 大小: %zd 字节 | 前部 Hex: %@",
               res, mb_hex_dump(buffer, res, 128));
    }
    return res;
}

static ssize_t my_write(int fildes, const void *buf, size_t nbyte) {
    if (buf && nbyte > 0 && is_ssl_socket(fildes)) {
        if (mb_mns_capture_armed()) {
            mb_dump_first_frame("DGW_write", (void *)(uintptr_t)fildes, buf, nbyte);
        } else {
            MBLogI(@"DGW_MNS_TX", @"🚀 [MNS Socket TX(write)] 大小: %zu 字节 | 前部 Hex: %@",
                   nbyte, mb_hex_dump(buf, nbyte, 128));
        }
        if (nbyte > 16) mb_analyze_outbound_frame("write", (const uint8_t *)buf, nbyte);
    }
    return orig_write ? orig_write(fildes, buf, nbyte) : -1;
}

static ssize_t my_read(int fildes, void *buf, size_t nbyte) {
    ssize_t res = orig_read ? orig_read(fildes, buf, nbyte) : -1;
    if (res > 0 && buf && is_ssl_socket(fildes)) {
        MBLogI(@"DGW_MNS_RX", @"📥 [MNS Socket RX(read)] 大小: %zd 字节 | 前部 Hex: %@",
               res, mb_hex_dump(buf, res, 128));
    }
    return res;
}

// ----------------------------------------------------------------------------
// 8.4 MCCWStreamSend 与 DGW 上层数据流监控
// ----------------------------------------------------------------------------
typedef int (*MCCWStreamConnect_ptr_t)(void *transport, void *options);
static MCCWStreamConnect_ptr_t orig_MCCWStreamConnect = NULL;

typedef int (*MCCWStreamSend_ptr_t)(void *transport, const void *data, size_t length);
static MCCWStreamSend_ptr_t orig_MCCWStreamSend = NULL;

typedef int (*MCCWStreamRegisterReceiveHandler_ptr_t)(void *transport, void *handler, void *context);
static MCCWStreamRegisterReceiveHandler_ptr_t orig_MCCWStreamRegisterReceiveHandler = NULL;

static int my_MCCWStreamConnect(void *transport, void *options) {
    MBLogI(@"MCCW_STREAM", @"🔌 [MCCWStreamConnect] transport: %p | options: %p", transport, options);
    return orig_MCCWStreamConnect ? orig_MCCWStreamConnect(transport, options) : 0;
}

static int my_MCCWStreamSend(void *transport, const void *data, size_t length) {
    if (data && length > 0) {
        MBLogI(@"MCCW_STREAM", @"🚀 [MCCWStreamSend] transport: %p | 大小: %zu 字节 | 前部 Hex: %@",
               transport, length, mb_hex_dump(data, length, 256));
    }
    return orig_MCCWStreamSend ? orig_MCCWStreamSend(transport, data, length) : 0;
}

static int my_MCCWStreamRegisterReceiveHandler(void *transport, void *handler, void *context) {
    MBLogI(@"MCCW_STREAM", @"📥 [MCCWStreamRegisterReceiveHandler] transport: %p | handler: %p", transport, handler);
    return orig_MCCWStreamRegisterReceiveHandler ? orig_MCCWStreamRegisterReceiveHandler(transport, handler, context) : 0;
}

// ----------------------------------------------------------------------------
// 8.5 MNSStreamTransport Objective-C 监控
// ----------------------------------------------------------------------------
%hook MNSStreamTransport

- (void)connect {
    MBLogI(@"MNS_OBJC", @"🔌 [MNSStreamTransport connect] 正在建立 MNS 长连接...");
    %orig;
}

- (void)handleNetworkStateChange:(id)arg1 {
    MBLogI(@"MNS_OBJC", @"🔄 [MNSStreamTransport handleNetworkStateChange] 网络状态变更: %@", arg1);
    %orig;
}

- (void)close {
    MBLogI(@"MNS_OBJC", @"🛑 [MNSStreamTransport close] 长连接关闭");
    %orig;
}

%end

// ----------------------------------------------------------------------------
// 8.6 [已禁用] MSGThreadViewMessageSendManager 发信方法监控
//   原因: 该方法真实签名中部分参数并非 Objective-C 对象, 在 ARC %hook 入口处被
//         自动 objc_retain 会导致 EXC_BAD_ACCESS 崩溃 (见 16:08 崩溃报告)。
//         发信明文已由 session_cipher_encrypt hook 完整捕获, 无需此 hook。
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// 8.7 结论#4 验证: 设备公钥在线拉取 (Java 靠预导入 iPhone 会话, 真机在线获取)
// ----------------------------------------------------------------------------
%hook MinosSDK

- (void)fetchMessagingPublicKeysWithSource:(id)source mailbox:(id)mailbox graphQLService:(id)gql contactIds:(id)contactIds useCase:(id)useCase syncIntervalSeconds:(id)interval lastSyncTimestamp:(id)lastSync enableDeltaOptimization:(BOOL)delta completion:(id)completion {
    MBLogI(@"E2EE-VERIFY", @"[结论#4][设备拉取] ✅ MinosSDK 在线拉取设备公钥 (GraphQL) —— contactIds=%@ useCase=%@ (证明真机在线获取对端设备, 而非预导入)",
           contactIds, useCase);
    %orig;
}

%end

%hook LightSpeedCryptoTAM

- (void)fetchDevicesForThreadKey:(id)threadKey contactId:(id)contactId mailboxType:(unsigned long long)mailboxType completion:(id)completion {
    MBLogI(@"E2EE-VERIFY", @"[结论#4][设备拉取] ✅ LightSpeedCryptoTAM 按会话拉取设备列表 —— threadKey=%@ contactId=%@ (真机动态设备发现)",
           threadKey, contactId);
    %orig;
}

- (void)fetchDevicesForThreadKey:(id)threadKey userId:(id)userId mailboxType:(unsigned long long)mailboxType databaseConnection:(id)db completion:(id)completion {
    MBLogI(@"E2EE-VERIFY", @"[结论#4][设备拉取] ✅ LightSpeedCryptoTAM(userId) 拉取设备 —— threadKey=%@ userId=%@",
           threadKey, userId);
    %orig;
}

%end

// ============================================================================
// 9. 构造函数初始化 (Plugin Entry Point)
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
        MBLogI(@"Init", @"🎉 MessengerBypass 插件加载就绪 (E2EE 深度监控增强版)");
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

        // 注册 SQLite E2EE 监控 Hook
        void *p_sqlite3_prepare = dlsym(RTLD_DEFAULT, "sqlite3_prepare_v2");
        if (p_sqlite3_prepare) MSHookFunction(p_sqlite3_prepare, (void *)my_sqlite3_prepare_v2, (void **)&orig_sqlite3_prepare_v2);
        void *p_sqlite3_bind_blob = dlsym(RTLD_DEFAULT, "sqlite3_bind_blob");
        if (p_sqlite3_bind_blob) MSHookFunction(p_sqlite3_bind_blob, (void *)my_sqlite3_bind_blob, (void **)&orig_sqlite3_bind_blob);
        void *p_sqlite3_bind_text = dlsym(RTLD_DEFAULT, "sqlite3_bind_text");
        if (p_sqlite3_bind_text) MSHookFunction(p_sqlite3_bind_text, (void *)my_sqlite3_bind_text, (void **)&orig_sqlite3_bind_text);

        // 注册 Signal Protocol 加解密 Hook
        void *p_cipher_enc = dlsym(RTLD_DEFAULT, "session_cipher_encrypt") ?: dlsym(RTLD_DEFAULT, "_session_cipher_encrypt");
        if (p_cipher_enc) {
            MSHookFunction(p_cipher_enc, (void *)my_session_cipher_encrypt, (void **)&orig_session_cipher_encrypt);
            MBLogI(@"Init", @"✅ 成功挂钩 Signal session_cipher_encrypt: %p", p_cipher_enc);
        }
        // [已禁用] Signal 解密 hook (session_cipher_decrypt_signal_message)
        // 原因: 该 hook 路径不稳定, 在 -13(17:48) 与 -15(20:42) 两次崩溃中均出现在栈顶,
        //       表现为 EXC_BAD_ACCESS/SIGSEGV (崩在原始解密 EVP_CIPHER_CTX_cipher 内部)。
        //       解密属于"收消息", 而本项目 5 条结论验证的是"发消息"(加密/franking/DGW帧),
        //       故移除解密 hook 以保证 App 稳定运行, 不影响任何验证目标。
        // void *p_cipher_dec = dlsym(RTLD_DEFAULT, "session_cipher_decrypt_signal_message") ?: dlsym(RTLD_DEFAULT, "_session_cipher_decrypt_signal_message");
        // if (p_cipher_dec) {
        //     MSHookFunction(p_cipher_dec, (void *)my_session_cipher_decrypt_signal_message, (void **)&orig_session_cipher_decrypt_signal_message);
        //     MBLogI(@"Init", @"✅ 成功挂钩 Signal session_cipher_decrypt_signal_message: %p", p_cipher_dec);
        // }

        // 结论#4/#5 验证: X3DH 会话建立 / 群聊 sender_key store (PreKey 解密 hook 同样禁用, 原因同上)
        // void *p_dec_prekey = dlsym(RTLD_DEFAULT, "session_cipher_decrypt_pre_key_signal_message") ?: dlsym(RTLD_DEFAULT, "_session_cipher_decrypt_pre_key_signal_message");
        // if (p_dec_prekey) {
        //     MSHookFunction(p_dec_prekey, (void *)my_session_cipher_decrypt_pre_key, (void **)&orig_session_cipher_decrypt_pre_key);
        //     MBLogI(@"Init", @"✅ [验证] 挂钩 session_cipher_decrypt_pre_key_signal_message: %p", p_dec_prekey);
        // }
        void *p_pkbundle = dlsym(RTLD_DEFAULT, "session_builder_process_pre_key_bundle") ?: dlsym(RTLD_DEFAULT, "_session_builder_process_pre_key_bundle");
        if (p_pkbundle) {
            MSHookFunction(p_pkbundle, (void *)my_session_builder_process_pre_key_bundle, (void **)&orig_session_builder_process_pre_key_bundle);
            MBLogI(@"Init", @"✅ [验证] 挂钩 session_builder_process_pre_key_bundle: %p", p_pkbundle);
        } else {
            MBLogW(@"Init", @"⚠️ [验证] 未找到 session_builder_process_pre_key_bundle 符号");
        }
        void *p_skstore = dlsym(RTLD_DEFAULT, "signal_protocol_store_context_set_sender_key_store") ?: dlsym(RTLD_DEFAULT, "_signal_protocol_store_context_set_sender_key_store");
        if (p_skstore) {
            MSHookFunction(p_skstore, (void *)my_set_sender_key_store, (void **)&orig_set_sender_key_store);
            MBLogI(@"Init", @"✅ [验证] 挂钩 signal_protocol_store_context_set_sender_key_store: %p", p_skstore);
        } else {
            MBLogW(@"Init", @"⚠️ [验证] 未找到 set_sender_key_store 符号");
        }

        // [已禁用] 原始 libc socket 抓包 Hook (send/recv/write/read)
        // 原因: 全局 hook 这些超高频 libc 函数会在 DNS 解析线程/系统线程/文件IO 上触发,
        //       导致 libnetwork 内部 sa_dst_fill_netsrc 调用 send() 时崩溃 (EXC_BREAKPOINT)。
        //       且这些只能拿到 TLS 加密字节, 对 E2EE 验证无价值 —— 我们已通过 SSL_write/SSL_read
        //       (BoringSSL 明文层) 和 session_cipher_encrypt (Signal 明文/密文) 获取所需数据。
        // void *p_send = dlsym(RTLD_DEFAULT, "send");
        // if (p_send) MSHookFunction(p_send, (void *)my_send, (void **)&orig_send);
        // void *p_recv = dlsym(RTLD_DEFAULT, "recv");
        // if (p_recv) MSHookFunction(p_recv, (void *)my_recv, (void **)&orig_recv);
        // void *p_write = dlsym(RTLD_DEFAULT, "write");
        // if (p_write) MSHookFunction(p_write, (void *)my_write, (void **)&orig_write);
        // void *p_read = dlsym(RTLD_DEFAULT, "read");
        // if (p_read) MSHookFunction(p_read, (void *)my_read, (void **)&orig_read);

        // 注册 MCCWStream Hook
        void *p_mccw_connect = dlsym(RTLD_DEFAULT, "_MCCWStreamConnect") ?: dlsym(RTLD_DEFAULT, "MCCWStreamConnect");
        if (p_mccw_connect) {
            MSHookFunction(p_mccw_connect, (void *)my_MCCWStreamConnect, (void **)&orig_MCCWStreamConnect);
            MBLogI(@"Init", @"✅ 成功挂钩 _MCCWStreamConnect (Addr: %p)", p_mccw_connect);
        }
        void *p_mccw_send = dlsym(RTLD_DEFAULT, "_MCCWStreamSend") ?: dlsym(RTLD_DEFAULT, "MCCWStreamSend");
        if (p_mccw_send) {
            MSHookFunction(p_mccw_send, (void *)my_MCCWStreamSend, (void **)&orig_MCCWStreamSend);
            MBLogI(@"Init", @"✅ 成功挂钩 _MCCWStreamSend (Addr: %p)", p_mccw_send);
        }
        void *p_mccw_register = dlsym(RTLD_DEFAULT, "_MCCWStreamRegisterReceiveHandler") ?: dlsym(RTLD_DEFAULT, "MCCWStreamRegisterReceiveHandler");
        if (p_mccw_register) {
            MSHookFunction(p_mccw_register, (void *)my_MCCWStreamRegisterReceiveHandler, (void **)&orig_MCCWStreamRegisterReceiveHandler);
            MBLogI(@"Init", @"✅ 成功挂钩 _MCCWStreamRegisterReceiveHandler (Addr: %p)", p_mccw_register);
        }

        // 注册 SSL 动态库监听与 Hook
        try_hook_ssl_symbols();
        _dyld_register_func_for_add_image(on_image_added);

        // 注册 Mailbox SDK 发信成功通知监听
        [[NSNotificationCenter defaultCenter] addObserverForName:nil object:nil queue:nil usingBlock:^(NSNotification *note) {
            NSString *name = note.name;
            if ([name containsString:@"MCAMailbox"] || [name containsString:@"Tam"] || [name containsString:@"Send"] || [name containsString:@"Message"]) {
                MBLogI(@"SDK_EVENT", @"🔔 [SDK Event] 通知: %@ | UserInfo: %@", name, note.userInfo);
            }
        }];

        MBLogI(@"Init", @"✅ 安全防护 Bypass 与 E2EE 全链路深度监控已全部激活");
        MBLogI(@"Init", @"🔬 [E2EE 交叉验证] 已启用 5 项结论验证 (grep 关键字 'E2EE-VERIFY'):");
        MBLogI(@"Init", @"   结论#1 DGW帧格式 / 结论#2 信封结构 / 结论#3 Franking / 结论#4 设备在线拉取 / 结论#5 libsignal+群聊");
    }
}
