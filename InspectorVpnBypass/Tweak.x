// ============================================================================
// InspectorVpnBypass - 自动化生成的安全防护 Bypass 插件
// 目标应用: InspectorVpn (com.github.zhkl0228.inspector.vpn)
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

#define LOG_TAG @"[InspectorVpnBypass] "
#define TLog(fmt, ...) NSLog(LOG_TAG fmt, ##__VA_ARGS__)

// ============================================================================
// 1. 反调试防护绕过模块 (Anti-Debug Bypass)
// ============================================================================

// ============================================================================
// 2. 越狱检测绕过模块 (Jailbreak Detection Bypass)
// ============================================================================

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

// ============================================================================
// 3. HTTPS 证书固定绕过模块 (SSL/TLS Pinning Bypass)
// ============================================================================

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
        TLog(@"=== InspectorVpnBypass 插件加载成功，正在注册安全防护 Bypass 逻辑 ===");
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "_dyld_get_image_name"), (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        MSHookFunction((void *)dlsym(RTLD_DEFAULT, "connect"), (void *)my_connect, (void **)&orig_connect);

        TLog(@"=== 安全防护 Bypass 规则已全部挂钩生效 ===");
    }
}
