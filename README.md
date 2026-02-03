# frida-ios-dump (iOS 15+ 修复版)

> **环境信息**:
> *   **Frida 版本**: 17.6.2
> *   **测试对象**: WhatsApp Messenger
> *   **App 版本**: 26.3.75 (Build 870636134)


这是一个基于 Frida 的 iOS 砸壳工具，可以从越狱设备中一键拉取并解密 IPA 文件。
**本分支针对 iOS 15+ 进行了深度修复，解决了 Header 解析错误和文件传输不稳定的问题。**

## 核心修复内容

1.  **iOS 15+ 完美支持**：
    *   修复了 `dump.js` 在新版内核下无法正确读取 Mach-O Header 的问题。
    *   修正了 `cryptid` 复位逻辑，确保解密后的 IPA 也是 clean 的。
    *   即使没有 `LC_ENCRYPTION_INFO` 常量定义也能正确识别加密段。

2.  **传输稳定性增强**：
    *   弃用了不稳定的 Python `scp` 库。
    *   直接调用系统原生 `scp` 命令，解决了大文件传输中断或 0KB 的问题。

## 使用环境准备

1.  **iOS 设备端**：
    *   设备已越狱。
    *   在 Cydia/Sileo 中安装 `Frida` (推荐 16.x 或更高)。
    *   确保安装了 `OpenSSH` 并且可以连接。
    *   **建议**：在运行前，先在手机上打开目标 App。

2.  **电脑端 (macOS)**：
    *   安装 Python 3.x。
    *   安装依赖库：
        ```bash
        sudo pip3 install -r requirements.txt --upgrade
        ```
    *   建立端口转发 (默认使用 2222 端口转发手机的 22 端口)：
        ```bash
        iproxy 2222 22
        ```

## 使用方法

### 基本用法

运行 `dump.py`，后面跟上 **App 名称** (显示名称) 或 **Bundle ID**。

```bash
python3 dump.py WhatsApp
```
或者
```bash
python3 dump.py net.whatsapp.WhatsApp
```

### 参数说明

```bash
python3 dump.py [以及参数] <Target>

位置参数:
  Target                App 的显示名称 或 Bundle ID

可选参数:
  -o OUTPUT, --output OUTPUT
                        指定生成的 IPA 文件名 (例如: -o MyDecryptedApp.ipa)
  -u USER, --user USER  SSH 用户名 (默认为 root)
  -p PORT, --port PORT  SSH 端口号 (默认为 2222)
  -h, --help            显示帮助信息
```

### 示例

```bash
# 使用默认配置砸壳 WhatsApp
python3 dump.py WhatsApp

# 指定 SSH 端口和输出文件名
python3 dump.py -p 2222 -o WeChat_Decrypted.ipa com.tencent.xin
```

## 注意事项 & 常见问题 (FAQ)

### 1. 密码问题
脚本默认配置的 root 密码为 `88888888` (在 `dump.py` 头部配置)。
*   如果你的设备密码是默认的 `alpine`，请手动修改 `dump.py` 第 26 行，或者使用 SSH Key 免密登录。
*   建议配置 SSH Key 以获得最佳体验。

### 2. 关于 "0.00B" 或传输卡死
如果你在旧版工具中遇到文件大小为 0 的问题，本版本已通过调用系统 `scp` 修复。请确保你的电脑终端可以正常运行 `scp` 命令。

### 3. SSH 连接失败
请检查：
*   手机是否已通过 USB 连接。
*   `iproxy 2222 22` 是否正在运行且没有报错。
*   能否通过终端手动连接：`ssh -p 2222 root@127.0.0.1`。

### 4. 报错 "Unable to attach"
*   请尝试**先在手机上并手动打开 App**，保持在前台运行，然后再运行脚本。
*   确保手机屏幕没有锁定。


## 成功验证案例 (Verified Cases)

以下应用已使用本工具成功砸壳并验证：

| 应用名称 | Bundle ID | 验证时间 | 备注 |
| :--- | :--- | :--- | :--- |
| **WhatsApp** | `net.whatsapp.WhatsApp` | 2026-02-03 | 基础兼容性测试通过 |
| **InspectorVpn** | `com.github.zhkl0228.inspector.vpn` | 2026-02-03 | 验证了新版 Frida 模块枚举修复 |
| **Telegram** | `org.telegram.Telegram` | 2026-02-03 | 大体积 IPA 验证通过 |

---
Happy Hacking!
