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

### 2. 静态安全防护检测、ObjC/Swift 逆向、Xrefs 交叉引用、Headless 反汇编、调用图与动态探针派生
- **调用脚本**: 
  - 常规安全分析: `python3 analyze.py -f <target.ipa>`
  - 导出/检索类与方法定义 (支持 Swift 还原名检索): `python3 analyze.py -f <target.ipa> --dump-objc [Keyword]`
  - ARM64 交叉引用反查 (定位敏感特征引用函数): `python3 analyze.py -f <target.ipa> --xrefs [Keyword]`
  - Headless 精准函数反汇编 (免开 IDA 秒看函数汇编): `python3 analyze.py -f <target.ipa> --disasm <OffsetOrSymbol>`
  - ARM64 函数调用图与多级拓扑树追溯: 
    - 查谁调用了它 (上游调用链): `python3 analyze.py -f <target.ipa> --callers <Offset/Symbol> [--depth 2]`
    - 查它调用了谁 (下游子调用树): `python3 analyze.py -f <target.ipa> --callees <Offset/Symbol> [--depth 2] [--export-mermaid callgraph.md]`
  - 静态一键派生 Frida 动态追踪探针: `python3 analyze.py -f <target.ipa> --gen-trace <Offset1,Offset2> [--trace-output trace.js]`
  - 独立 Swift & C++ (Itanium ABI) 符号秒级还原: `python3 analyze.py --demangle <MangledSymbol>`
  - [阶段一] 跨版本函数特征码生成与秒级自动对齐: 
    - 提取特征: `python3 analyze.py -f <target.ipa> --gen-sig <Offset/Symbol>`
    - 跨版本对齐: `python3 analyze.py -f <new_target.ipa> --find-sig "<Pattern>"`
  - [阶段二] 函数控制流图 (CFG) 基本块切分与 Mermaid 可视化:
    - 终端拓扑解析: `python3 analyze.py -f <target.ipa> --cfg <Offset/Symbol>`
    - 导出 Mermaid 图: `python3 analyze.py -f <target.ipa> --cfg <Offset/Symbol> --export-cfg <file.md>`
  - [阶段三] ARM64 指令热修补与 Frida 运行时 Patch 派生:
    - 静态修补二进制: `python3 analyze.py -f <target.ipa> --patch "<Offset/Symbol>:<Action>" [--patch-output <file>]`
    - 导出免改原文件 Frida 内存热补丁: `python3 analyze.py -f <target.ipa> --patch "<Offset/Symbol>:<Action>" --patch-script <file.js>`
  - 结构化字符串与 CoreFoundation 常量提取 (突破盲猜关键词):
    - 提取并检索常量字典: `python3 analyze.py -f <target.ipa> --dump-strings [Keyword] [--string-type cfstring|ustring|cstring]`
    - 导出全量常量表: `python3 analyze.py -f <target.ipa> --dump-strings --strings-output strings.json`
  - 原生沙盒特权 (Entitlements) 提取 (离线获取 Keychain 组与 AppGroup 容器):
    - 终端打印特权报表: `python3 analyze.py -f <target.ipa> --dump-entitlements`
    - 导出 plist/json 文件: `python3 analyze.py -f <target.ipa> --dump-entitlements --entitlements-output entitlements.plist`
  - 动态链接库依赖拓扑树与导入符号审计 (摸底底层通信与安全选型):
    - 终端打印依赖树与符号分类: `python3 analyze.py -f <target.ipa> --dump-deps`
    - 导出 markdown/json 报表: `python3 analyze.py -f <target.ipa> --dump-deps --deps-output deps_report.md`
  - 滑动窗口香农熵 (Entropy) 扫描 (定位白盒加密密钥表与混淆块):
    - 终端扫描高熵块: `python3 analyze.py -f <target.ipa> --entropy [--entropy-threshold 7.2]`
    - 导出报表: `python3 analyze.py -f <target.ipa> --entropy --entropy-output entropy.md`
- **触发时机**: 
  1. 面对全新 App 的“摸底”阶段：探测应用是否有**反调试 (ptrace/sysctl)**、**越狱检测**、**强 SSL Pinning** 或对 **Frida 的查杀**；静态报告会自动标识特征被哪个函数引用 (`func@0x...`)；
  2. **逆向业务协议或符号被 strip 剥离时**：需要快速掌握 App 内部有哪些 Controller、Manager、Service，或寻找特定业务关键字（如 `Message`、`Session`、`Socket`、`Crypto`）的类名与方法签名时；
  3. **定位敏感调用点以实施精确 Hook 时**：通过 `--xrefs <keyword>` 秒级反查引用该特征的汇编函数偏移 (`caller_func_offset`)，免去在 IDA 中手动交叉引用的繁琐操作；
  4. **深入判断函数底层实现（免开 IDA / Hopper）**：拿到函数偏移或发现特征后，通过 `--disasm <Offset/Symbol>` 直接截取该函数的 ARM64 汇编指令片段（带字符串常量内联注释与系统调用识别），秒级掌握该函数的具体逻辑与返回时机；
  5. **梳理调用链与核心业务主路径**：通过 `--callers` 快速理清某底层 API 是由哪些业务函数调起（回溯触发源），通过 `--callees` 顺藤摸瓜掌握该函数内部按序触发的子任务（理清算法分发流程）；
  6. **快速进入真机动态验证闭环**：通过 `--gen-trace <Offsets>` 一键生成具备自动 ASLR 基址重定位、智能入参嗅探、调用栈打印与耗时统计的 Frida 探针，直接上机验证；
  7. **面对跨版本发版导致硬编码偏移失效时**：通过 `--gen-sig` 提取核心函数指令序列并自动遮罩动态操作数，再通过 `--find-sig` 在新版 IPA 中秒级自动对齐新偏移，实现 Hook 脚本与逆向成果的零成本迁移；
  8. **分析复杂状态机、分支跳转与多返回路径函数时**：通过 `--cfg` 自动切分汇编基本块并导出 Mermaid 控制流图，一眼洞悉循环结构、跳出条件与异常分支；
  9. **需强行绕过特定条件判断、反调试或强行置位时**：通过 `--patch <Target>:NOP/RET_TRUE` 静态生成修补后的二进制，或一键导出 Frida 内存热修补脚本（动态 `Memory.protect` 修改执行权限并写入机器码），无需重新打包安装即可立即测试；
  10. **面对未知或去符号大模块摸底时**：通过 `--dump-strings [keyword]` 提取全量结构化 CFString 与宽字符 UString，快速获取协议任务名、配置项或路由常量，拿其 VA 作为线索输入 `--xrefs` 形成闭环；
  11. **需定位真机 Keychain 共享组或 AppGroup 沙盒数据库路径时**：通过 `--dump-entitlements` 离线秒级提取 Mach-O 中的特权清单，无需开机即可明确 `keychain-access-groups` 与 `application-groups`；
  12. **需摸底应用动态库依赖拓扑或通信栈底层符号时**：通过 `--dump-deps` 离线秒级提取全部 `LC_LOAD_DYLIB` 与 Undefined 导入符号，掌握网络、加密与多线程基础库选型；
  13. **面对白盒加固、高混淆或寻找内嵌加密密钥表时**：通过 `--entropy` 扫描滑动窗口香农熵，快速发现异常高熵区间 (H >= 7.2)，定位白盒密钥表、S-Box 或 OLLVM 混淆区域。
- **AI 行动指南**: 
  - 给它喂入砸壳后的 IPA，工具会自动解析 `__objc_classlist`、`__objc_catlist` 并建立 ARM64 指令 xrefs；
  - 若需要探测白盒密钥、混淆块与高熵加密数据，运行 `python3 analyze.py -f <target.ipa> --entropy`；
  - 若需要摸底动态库依赖拓扑与通信底座选型，运行 `python3 analyze.py -f <target.ipa> --dump-deps`；
  - 若需要提取应用沙盒权限与 Keychain 访问组，运行 `python3 analyze.py -f <target.ipa> --dump-entitlements`；
  - 若需要摸底常量字典与协议配置线索，运行 `python3 analyze.py -f <target.ipa> --dump-strings [Keyword]` 提取结构化常量；
  - 若需要定位特定业务类，运行 `python3 analyze.py -f <target.ipa> --dump-objc <Keyword>` 快速打印 `@interface` 结构（含 Swift 还原标签）；
  - 若需要定位反调试/防护逻辑执行体，运行 `python3 analyze.py -f <target.ipa> --xrefs <keyword>` 提取调用者函数 Offset；
  - 若需要快速研判函数控制流，运行 `python3 analyze.py -f <target.ipa> --disasm <Offset>` 查看汇编实现，快速决定 Hook 点或 Patch 策略；
  - 若需要回溯业务调用链路，运行 `python3 analyze.py -f <target.ipa> --callers <Offset>` 或 `--callees <Offset>` 快速建立调用图；
  - 若需要分析复杂函数的完整逻辑走向，运行 `python3 analyze.py -f <target.ipa> --cfg <Offset> --export-cfg cfg.md` 可视化控制流分支；
  - 若需要迁移新版本偏移，运行 `python3 analyze.py -f <old.ipa> --gen-sig <Offset>`，并在新版本上执行 `--find-sig "<pattern>"` 自动化更新代码；
  - 若需要强行绕过检测或测试逻辑分支，运行 `python3 analyze.py -f <target.ipa> --patch "<Offset>:RET_TRUE" --patch-script patch.js` 快速上机生效；
  - 若需要立刻上机验证，运行 `python3 analyze.py -f <target.ipa> --gen-trace <Offset> -o trace.js` 生成探针并挂钩目标 App。

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
