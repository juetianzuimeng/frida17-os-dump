# InspectorVpnBypass

自动化生成的 iOS 安全防护 Bypass 插件与动态调试脚本。

- **目标应用**: `InspectorVpn`
- **Bundle ID**: `com.github.zhkl0228.inspector.vpn`
- **可执行文件**: `InspectorVpn`

---

## 🛠 方法一：使用 Theos 编译并安装到越狱设备

### 1. 环境准备
确保已安装 Theos (https://theos.dev/)。

### 2. 编译插件
```bash
# 进入当前插件目录
cd InspectorVpnBypass

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
frida -U -f com.github.zhkl0228.inspector.vpn -l bypass.js

# 或附加到已运行的 App
frida -U -n "InspectorVpn" -l bypass.js
```
