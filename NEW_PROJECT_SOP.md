# 🚀 iOS 新逆向项目标准起步流程与架构指南 (SOP)

本指南旨在为开启一个全新的 iOS 逆向与协议复刻项目（如 WhatsApp、Telegram 等）提供一套**标准化的目录规范**与**工业化的起步工作流**。

所有的基础逆向能力（砸壳、静态分析、插件生成、自动部署）均由跨工作区底层兵器库统一提供：
👉 **`/Users/mx/zengshangchun/ioshook/frida-ios-dump`**

> **铁律**：新的业务复刻项目中，严禁拷贝底层分析与部署脚本。所有针对真机的逆向操作，必须通过绝对路径调用上述兵器库的能力！生成的 Tweak 越狱插件工程则必须保存在业务项目内部以实现代码隔离和业务定制。

---

## 📂 第一部分：标准化项目目录结构 (The Architecture)

在新建的逆向业务工程（例如 `WhatsApp-iOS-Re`）中，请首先建立以下标准目录结构：

```text
/Users/mx/IdeaProjects/<Your-New-Project>/
├── ipa_analysis/       # 资产区：存放兵器库砸壳提取的 .ipa、解包后的二进制文件及静态安全分析报告。
├── tweak/              # 逆向区：存放由兵器库自动生成的专属 Bypass 越狱插件工程（Makefile, Tweak.x 等）。
├── logs/               # 日志区：存放运行时的所有真值现场。
│   ├── vpn/            # 存放按天切割的网络抓包流量日志（vpn-YYYY-MM-DD.log）。
│   └── tweak/          # 存放从真机回传的底层 Hook 探针日志。
├── evidence/           # 沉淀区：存放协议地基和分析依据。任何关键加密算法和数据结构，写代码前先在此固化证据。
├── docs/               # 文档区：存放攻关计划（Plan）、交接文档（Handover）以及向 AI 发布的指令规范（AGENTS.md）。
└── src/                # 复刻区：最终的业务复刻代码（如 Java、Python 或 Go 实现的加解密或发信客户端）。
```

---

## ⚙️ 第二部分：标准的 5 步起步工作流 (The 5-Step Workflow)

当确立目标 App 后，不论是你本人还是 AI Agent，请严格按照以下步骤推进，快速搭建一个**无干扰、全监控**的纯净逆向环境：

### Step 1: 砸壳提取 (Dump & Extract)
*   **目标**：获取无壳的 App 二进制文件，为后续 IDA 反编译和静态特征扫描做准备。
*   **操作**：确保 iPhone 已连接 USB，目标 App 在前台运行。调用兵器库进行砸壳，并将产物移动到当前业务项目。
*   **命令示例**：
    ```bash
    cd /Users/mx/zengshangchun/ioshook/frida-ios-dump
    python3 dump.py <TargetAppName> -o /Users/mx/IdeaProjects/<Your-New-Project>/ipa_analysis/<TargetAppName>.ipa
    ```

### Step 2: 静态安全摸底 (Static Security Audit)
*   **目标**：掌握敌情，明确 App 是否含有越狱检测、反调试 (ptrace/sysctl)、SSL Pinning 强校验或针对 Frida 的探针。
*   **操作**：回到你的新业务工程根目录，调用兵器库引擎分析上一步获取的 IPA，将报告输出到当前资产区。
*   **命令示例**：
    ```bash
    python3 /Users/mx/zengshangchun/ioshook/frida-ios-dump/analyze.py \
      -f ipa_analysis/<TargetAppName>.ipa \
      -o ipa_analysis/ipa_security_report.md
    ```

### Step 3: 自动生成与部署专属探针 (Bypass & Scaffold Tweak)
*   **目标**：一键生成自带“防护绕过”底盘的 Theos 插件工程，为业务 Hook 提供安全沙盒，并实现极速的真机部署闭环。
*   **操作**：
    1. **生成工程**：让兵器库读取分析结果，把针对性屏蔽了安全机制的纯净底座代码吐在当前项目的 `tweak/` 目录下。
       ```bash
       python3 /Users/mx/zengshangchun/ioshook/frida-ios-dump/gen_tweak.py \
         -f ipa_analysis/<TargetAppName>.ipa \
         -o ./tweak
       ```
    2. **编写业务逻辑**：进入 `./tweak/Tweak.x`，在绕过代码的下方，添加你要监控的核心密码学 / SQLite / 网络收发函数的业务 Hook 代码。
    3. **一键极速部署**：编译打包并利用兵器库自动将其推送到真机执行。
       ```bash
       python3 /Users/mx/zengshangchun/ioshook/frida-ios-dump/install_deb.py ./tweak -k <TargetAppName>
       ```

### Step 4: 挂载通用监控与日志回传 (Monitor & Pull Logs)
*   **目标**：对于极度混淆的控制流或加密协议，利用兵器库的高阶探针强捞明文，并自动将真机上生成的日志证据带回开发环境。
*   **操作**：
    1. 若找不到函数入口，直接使用兵器库的高阶网络/堆栈探针（修改探针顶部 CONFIG 后注入）：
       ```bash
       frida -U -f <BundleID> -l /Users/mx/zengshangchun/ioshook/frida-ios-dump/probes/network/stack_aead_scanner.js
       ```
    2. 自动化拉回在真机沙盒内生成的 Tweak 日志文件：
       ```bash
       /Users/mx/zengshangchun/ioshook/frida-ios-dump/scripts/pull_device_logs.sh \
         -a <TargetAppName> -o ./logs/tweak/
       ```

### Step 5: 固化证据与复刻业务 (Evidence & Replication)
*   **目标**：杜绝在没有任何证据的情况下盲目凭空猜测通信参数或密码学流程，一切用事实说话。
*   **操作**：
    1. 将 IDA/Hopper 中的伪代码特征与 `logs/` 下捕获的真机时间线日志进行双向交叉比对验证；
    2. 将确认的算法流转拓扑与 Protobuf 载荷字段结构，第一时间以 Markdown 形式写入 `evidence/` 目录进行“固化”；
    3. 证据确凿且逻辑完美闭环后，最终在 `src/` 目录下进行 Java / Python 等语言的代码复刻开发与发信测试。
