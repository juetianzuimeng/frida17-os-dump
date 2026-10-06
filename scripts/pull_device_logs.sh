#!/usr/bin/env bash
# ==============================================================================
# 通用 iPhone 真机沙盒日志拉取工具 (General Device Log Puller)
# ==============================================================================

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 默认配置
SSH_HOST="${SSH_HOST:-127.0.0.1}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_USER="mobile"
SSH_PASS="88888888"

APP_KEYWORD=""
LOG_PATTERN="*.log"
OUT_DIR="$PROJECT_DIR/logs/sandbox"

usage() {
    echo "Usage: $0 -a <AppKeyword> [-p <LogPattern>] [-o <OutputDir>]"
    echo "Options:"
    echo "  -a   目标应用关键字或 Bundle ID (例如: Messenger, WhatsApp, org.telegram.Telegram)"
    echo "  -p   日志文件名匹配模式 (默认: *.log, 你可以指定 tweak-*.log)"
    echo "  -o   本地输出目录 (默认: ./logs/sandbox)"
    echo "  -h   显示帮助"
    exit 1
}

while getopts "a:p:o:h" opt; do
    case $opt in
        a) APP_KEYWORD="$OPTARG" ;;
        p) LOG_PATTERN="$OPTARG" ;;
        o) OUT_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$APP_KEYWORD" ]; then
    echo "[-] 必须使用 -a 指定目标应用关键字!"
    usage
fi

mkdir -p "$OUT_DIR"

SSH_CMD="sshpass -p $SSH_PASS ssh -F /dev/null -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password -p $SSH_PORT $SSH_USER@$SSH_HOST"
SCP_CMD="sshpass -p $SSH_PASS scp -F /dev/null -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password -P $SSH_PORT"

echo "[*] 正在连接真机 $SSH_USER@$SSH_HOST:$SSH_PORT 检索 $APP_KEYWORD 的沙盒日志..."

# 1. 自动寻找 App 沙盒路径 (使用 ls -d 配合 grep，或通过 plist 提取)
# 对于越狱机，我们可以搜索 /var/mobile/Containers/Data/Application 目录
echo "[*] 寻找应用沙盒目录..."
TARGET_SANDBOX=$($SSH_CMD "
    for dir in /var/mobile/Containers/Data/Application/*; do
        if [ -f \"\$dir/.com.apple.mobile_container_manager.metadata.plist\" ]; then
            if grep -iq \"$APP_KEYWORD\" \"\$dir/.com.apple.mobile_container_manager.metadata.plist\"; then
                echo \"\$dir\"
                break
            fi
        fi
    done
")

if [ -z "$TARGET_SANDBOX" ]; then
    echo "[-] 未找到匹配关键字 '$APP_KEYWORD' 的沙盒目录。请检查关键字或设备状态。"
    exit 1
fi

echo "[+] 定位到沙盒目录: $TARGET_SANDBOX"

# 2. 查找匹配的日志文件
REMOTE_LOGS=$($SSH_CMD "find \"$TARGET_SANDBOX\" -type f -name \"$LOG_PATTERN\" 2>/dev/null")

if [ -z "$REMOTE_LOGS" ]; then
    echo "[-] 沙盒中未找到匹配 '$LOG_PATTERN' 的日志文件。"
    exit 0
fi

echo "[+] 发现真机日志文件:"
echo "$REMOTE_LOGS"

# 3. 逐个拉取
for remote_file in $REMOTE_LOGS; do
    fname=$(basename "$remote_file")
    TODAY=$(date "+%Y-%m-%d")
    # 可以选择给日志加日期后缀避免覆盖
    dest_fname="${fname%.*}-${TODAY}.${fname##*.}"
    
    echo "[*] 同步 $fname -> $OUT_DIR/$dest_fname ..."
    $SCP_CMD "$SSH_USER@$SSH_HOST:$remote_file" "$OUT_DIR/$dest_fname"
done

echo "[+] 真机沙盒日志拉取并归档完成！保存在: $OUT_DIR"
