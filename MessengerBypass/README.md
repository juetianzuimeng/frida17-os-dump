# MessengerBypass

自动化生成的 iOS 安全防护 Bypass 插件与动态调试脚本（含异常诊断与网络请求失败监控系统）。

- **目标应用**: `Messenger`
- **Bundle ID**: `com.facebook.Messenger`
- **可执行文件**: `Messenger`

---

## 📋 核心功能与监控特性

1. **统一持久化日志系统**：
   - 同时输出到 **系统控制台**（`NSLog`，便于 `idevicesyslog` / Console 实时追踪）与 **应用沙盒持久化文件**（`MessengerBypass.log`）。
   - 自动包含毫秒级时间戳、线程信息、日志级别（DEBUG/INFO/WARN/ERROR/FATAL）与调用栈。
   - 自动文件大小保护（上限 10MB 自动轮换），防止耗尽手机存储。
2. **网络请求异常与失败深度监控**：
   - 监控 `NSURLSession` 核心请求（URL、Method、耗时、数据大小）。
   - 捕获并记录 HTTP `4xx` / `5xx` 异常状态码及响应摘要。
   - 捕获 `NSError` 详细域与错误码。
   - **特别高亮识别 SSL/TLS Pinning 证书握手失败**（如 `-1200`、`-1202` 等），输出高危告警 `[SSL Pinning 握手失败]`，便于直接定位是否为证书固定引起的问题。
3. **全局未捕获异常与 Crash 诊断**：
   - 捕获 Objective-C 未处理异常（`NSUncaughtExceptionHandler`），记录 Exception Name、Reason、UserInfo 及完整调用栈 `callStackSymbols`。
   - 捕获 POSIX 致命信号（`SIGSEGV`、`SIGBUS`、`SIGABRT`、`SIGILL`、`SIGFPE` 等），输出崩溃现场寄存器与 backtrace。
4. **全面的安全防护 Bypass 模块**：
   - 反调试（`sysctl P_TRACED`, `isatty`, `signal`, `task_set_exception_ports`）
   - 越狱检测拦截（`stat`, `access`, `fopen`, `NSFileManager`, `canOpenURL` 等）
   - HTTPS 证书固定绕过（`SecTrustEvaluate`, `SecTrustEvaluateWithError`, `AFSecurityPolicy`, `mbedtls_x509_crt_verify`, `LightSpeedEngine`）
   - Frida 默认端口扫描探测拦截

---

## 🔍 如何查看与提取异常日志

### 1. 本地持久化日志文件位置
插件会在应用启动时自动检测并输出日志文件的绝对路径：
- **主要路径**：`<App沙盒目录>/Documents/MessengerBypass.log`
- **备用路径**：`<App沙盒目录>/Library/Caches/MessengerBypass.log` 或 `<App沙盒目录>/tmp/MessengerBypass.log`

#### 提取方式：
- **方式 A (Filza / 越狱文件管理器)**：打开 Filza，进入 `/var/mobile/Containers/Data/Application/<Messenger>/Documents/`，即可直接打开查看 `MessengerBypass.log`。
- **方式 B (SSH / scp 导出到电脑)**：
  ```bash
  # 查找日志文件路径
  ssh root@<手机IP> "find /var/mobile/Containers/Data/Application/ -name 'MessengerBypass.log'"
  
  # 实时查看日志滚动输出 (tail -f)
  ssh root@<手机IP> "tail -f /var/mobile/Containers/Data/Application/<UUID>/Documents/MessengerBypass.log"
  ```

### 2. 通过系统控制台实时查看日志
在连接 USB 的 Mac 电脑上执行以下命令之一即可实时过滤插件日志：
```bash
# 方式 A: idevicesyslog (推荐)
idevicesyslog -m "MessengerBypass"

# 方式 B: log stream
ssh root@<手机IP> "log stream --predicate 'eventMessage contains \"MessengerBypass\"'"
```

---

## 🛠 方法一：使用 Theos 编译并安装到越狱设备

### 1. 环境准备
确保已安装 Theos (https://theos.dev/)。

### 2. 编译插件
```bash
# 进入当前插件目录
cd MessengerBypass

# 编译 deb 包 (支持 iOS 14 - 17 Rootless 与 Rootful, arm64 & arm64e)
make package FINALPACKAGE=1

# 或一键编译并安装到手机 (需配置 THEOS_DEVICE_IP=127.0.0.1 THEOS_DEVICE_PORT=2222)
make do
```

---

## ⚡ 方法二：使用 Frida 动态免编译即时加载

若不希望安装 Theos 编译环境，可直接使用附带的 `bypass.js` 进行动态拦截：

```bash
# 启动并挂钩目标 App
frida -U -f com.facebook.Messenger -l bypass.js

# 或附加到已运行的 App
frida -U -n "Messenger" -l bypass.js
```
