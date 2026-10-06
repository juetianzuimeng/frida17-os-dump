# 🤖 frida-ios-dump AI Agents 指南 (AI Behavior & Capability Guide)

## 🎯 核心定位 (Core Identity)
本工作区是你的全栈 **iOS 逆向与安全防护自动化兵器库**。
作为一个 AI，当用户指派你进行 iOS 逆向任务（如业务复刻、协议破解），或你在外部工作区（如 `messenger-ios`）遇到真机调试需求时，请**停止重复造轮子**。

关于 iOS 的砸壳、静态防护检测、Theos Tweak 生成、USB 自动部署、通用明文探针等操作，**必须优先调用本项目中的现成工具**。

---

## 🛠 能力地图与触发时机 (Capability Map)

### 1. 砸壳与应用解密 (Decryption)
- **调用脚本**: `python3 dump.py <BundleID or AppName>`
- **触发时机**: 当你在业务项目中需要深入分析官方的底层控制流、C++ 汇编结构或导出私有头文件时。
- **AI 行动指南**: 确保手机 USB 已连接且 App 在前台，调用该脚本将其砸壳并拉取到本地，供 IDA 或 Hopper 等工具（或本库的 `analyze.py`）分析。

### 2. 静态安全防护检测 (Static Security Analysis)
- **调用脚本**: `python3 analyze.py -f <target.ipa>`
- **触发时机**: 面对一个全新 App 的“摸底”阶段。你需要知道目标应用是否有**反调试 (ptrace/sysctl)**、**越狱检测**、**强 SSL Pinning** 或对 **Frida 的查杀**。
- **AI 行动指南**: 给它喂入砸壳后的 IPA，它会输出检测报告。基于此报告，你才能有的放矢地决定要 Hook 掉哪些防护函数。

### 3. Tweak 越狱插件自动生成 (Tweak Scaffolding)
- **调用脚本**: `python3 gen_tweak.py -f <target.ipa> -o ./<App>Bypass`
- **触发时机**: 当你需要长久、稳定地向 App 注入 Hook 代码（拦截网络、监控 DB），准备编写 Theos 工程时。
- **AI 行动指南**: 该脚本会自动整合 `analyze.py` 的扫描结果，全自动生成包含防护绕过规则的标准 Theos 工程框架（含 `Makefile`, `Tweak.x` 等）。你只需要在 `Tweak.x` 里补充自己的业务 Hook 代码即可。

### 4. iPhone USB 自动化部署 (Build & Deploy)
- **调用脚本**: `python3 install_deb.py ./<App>Bypass -k <AppKeyword>`
- **触发时机**: 当你修改完了 `Tweak.x`，需要推送到手机上运行验证时。
- **AI 行动指南**: 在 Tweak 工程下执行 `make package FINALPACKAGE=1` 后，直接调用此脚本。它会自动免密 SSH、sudo 提权、`dpkg -i` 安装并根据 `-k` 参数杀掉目标 App 进程使其重启生效，实现一键部署闭环。

### 5. 高级动态探针与日志辅助 (Probes & Scripts)
- **日志一键拉取**: `scripts/pull_device_logs.sh -a <AppName>`
  - **触发时机**: 真机上的 Tweak 正在输出大量 Hook 日志，你需要将其导回本地环境来比对分析。
- **通用底层探针库**: `probes/` 目录 (如 `stack_aead_scanner.js`, `stalker_tracer.js`)
  - **触发时机**: 当你发现 App 采用了魔改加密协议、底层网络请求被 CFG 混淆保护，常规函数入口失效时。
  - **AI 行动指南**: 阅读并根据目标环境（目标端口、偏移地址）修改探针顶部的 `CONFIG` 字典，将其直接注入或合并至 `bypass.js` 中探测明文。

---

## ⚠️ AI 能力沉淀与演进铁律 (Rule of Evolution)

如果你在针对某个具体 App（例如 Telegram, WhatsApp）的攻坚战中，遭遇并破解了**新型的安全防护**或写出了**高复用度的底层调试脚本**，**绝对禁止只将这些代码保留在对应的业务项目中**。

1. **新防护特征沉淀**：立即提取该防护特征，补充进本兵器库的 `analyzer/rules/` 静态引擎中，并联动 `gen_tweak.py`。
2. **新通用探针沉淀**：剥离业务相关（如特定的 Protobuf 解析）的硬编码内容，泛化为通用配置（`CONFIG`），归档至 `probes/`。

遵循**“攻克一城，利器入库，免疫天下”**的原则，使这个工具链始终保持最前沿的对抗能力。
