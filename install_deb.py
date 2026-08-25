#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用 iPhone 越狱插件 (deb 包) USB/SSH 自动化安装工具 (Install DEB to iPhone)
支持：
1. 自动从 '手机连接信息.txt' 读取 USB/SSH 连接配置 (Host, Port, User, Password)
2. 智能自适应 root 与 mobile 用户 (以 mobile 用户登录时自动使用 sudo 提权安装)
3. 自动将临时包上传至权限受控的家目录并执行 dpkg -i 安装
4. 智能定位目标 deb 文件或 Theos 工程 packages/ 下最新编译包
5. 兼容 Rootless (Dopamine/Palera1n/ElleKit) 与传统 Rootful 越狱
6. 安装后自动关闭并重载指定应用进程 (-k <ProcessName>) 或 Respring
"""

import argparse
import getpass
import glob
import os
import re
import sys
import time


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"


def load_default_config() -> dict:
    """尝试从当前目录下的 '手机连接信息.txt' 加载默认连接参数"""
    config = {
        "host": "127.0.0.1",
        "port": 2222,
        "user": "root",
        "password": "88888888"
    }

    info_files = ["手机连接信息.txt", "connection.txt", "ssh_config.txt"]
    for fname in info_files:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), fname)
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                m_host = re.search(r"Host\s*=\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
                m_port = re.search(r"Port\s*=\s*(\d+)", content, re.IGNORECASE)
                m_user = re.search(r"User\s*=\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
                m_pwd = re.search(r"Password\s*=\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)

                if m_host: config["host"] = m_host.group(1)
                if m_port: config["port"] = int(m_port.group(1))
                if m_user: config["user"] = m_user.group(1)
                if m_pwd: config["password"] = m_pwd.group(1)
                break
            except Exception:
                pass
    return config


def find_target_deb(target_path: str) -> str:
    """定位目标 deb 文件路径"""
    abs_path = os.path.abspath(target_path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"指定的路径不存在: {abs_path}")

    if os.path.isfile(abs_path):
        if abs_path.endswith(".deb"):
            return abs_path
        raise ValueError(f"目标文件不是有效的 .deb 软件包: {abs_path}")

    packages_dir = os.path.join(abs_path, "packages")
    search_dirs = [packages_dir, abs_path] if os.path.exists(packages_dir) else [abs_path]

    deb_files = []
    for s_dir in search_dirs:
        for f in glob.glob(os.path.join(s_dir, "*.deb")):
            deb_files.append(f)

    if not deb_files:
        raise FileNotFoundError(
            f"在目录 '{abs_path}' 或其 'packages/' 子目录中未找到任何 .deb 文件。\n"
            f"请先在工程目录下运行 'make package' 编译生成 deb 包。"
        )

    deb_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    return deb_files[0]


def connect_device(host: str, port: int, user: str, password: str = ""):
    """智能连接 iPhone (自动尝试 root/mobile 用户及密码)"""
    try:
        import paramiko
    except ImportError:
        return None, None, None, "未安装 paramiko 库"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # 用户名尝试列表
    user_list = [user]
    if "root" not in user_list: user_list.append("root")
    if "mobile" not in user_list: user_list.append("mobile")

    # 密码尝试列表
    pwd_list = []
    if password: pwd_list.append(password)
    for p in ["88888888", "alpine", "root"]:
        if p not in pwd_list: pwd_list.append(p)

    # 1. 尝试使用 Key 免密连接
    for u in user_list:
        try:
            client.connect(host, port=port, username=u, timeout=3, look_for_keys=True, allow_agent=True)
            return client, u, "", None
        except Exception:
            pass

    # 2. 尝试用户+密码组合连接
    for u in user_list:
        for p in pwd_list:
            try:
                client.connect(host, port=port, username=u, password=p, timeout=3, look_for_keys=False, allow_agent=False)
                return client, u, p, None
            except Exception:
                continue

    # 3. 若均失败，提示输入密码
    print(f"{Color.YELLOW}[!] 正在尝试交互式密码连接 (默认常用密码为 88888888 或 alpine):{Color.RESET}")
    for _ in range(3):
        try:
            user_pwd = getpass.getpass(f"Password for {user}@{host}:{port}: ")
            if not user_pwd: continue
            for u in user_list:
                try:
                    client.connect(host, port=port, username=u, password=user_pwd, timeout=4, look_for_keys=False, allow_agent=False)
                    return client, u, user_pwd, None
                except Exception:
                    pass
            print(f"{Color.RED}[-] 认证失败，请重新输入{Color.RESET}")
        except Exception as e:
            pass

    return None, None, None, "SSH 认证失败 (无法建立连接)"


def install_deb_package(client, auth_user: str, auth_pwd: str, deb_path: str, kill_process: str = None, respring: bool = False) -> bool:
    """上传并执行 dpkg 安装"""
    filename = os.path.basename(deb_path)
    # 根据用户权限选择合适的上传目录
    remote_tmp = f"/var/mobile/{filename}" if auth_user == "mobile" else f"/tmp/{filename}"

    # 1. SFTP 上传
    print(f"{Color.BLUE}[*] 正在通过 USB 高速传输安装包至 iPhone: {remote_tmp} ...{Color.RESET}")
    start_t = time.time()
    try:
        sftp = client.open_sftp()
        sftp.put(deb_path, remote_tmp)
        sftp.close()
    except Exception as e:
        print(f"{Color.RED}[-] 上传失败: {str(e)}{Color.RESET}", file=sys.stderr)
        return False
    print(f"{Color.GREEN}[+] 安装包传输完成 (耗时: {time.time() - start_t:.2f} 秒){Color.RESET}")

    # 2. 构造 dpkg 安装命令 (若是 mobile 用户则自动附加 sudo)
    prefix = f"echo '{auth_pwd}' | sudo -S " if (auth_user == "mobile" and auth_pwd) else ""
    
    install_script = f"""
    if [ -x /var/jb/usr/bin/dpkg ]; then
        {prefix}/var/jb/usr/bin/dpkg -i '{remote_tmp}'
    elif [ -x /usr/bin/dpkg ]; then
        {prefix}/usr/bin/dpkg -i '{remote_tmp}'
    else
        {prefix}dpkg -i '{remote_tmp}'
    fi
    RET=$?
    rm -f '{remote_tmp}'
    exit $RET
    """

    print(f"{Color.BLUE}[*] 正在手机端执行 dpkg -i 部署安装 ...{Color.RESET}")
    stdin, stdout, stderr = client.exec_command(install_script)
    out_text = stdout.read().decode("utf-8", errors="ignore").strip()
    err_text = stderr.read().decode("utf-8", errors="ignore").strip()
    exit_status = stdout.channel.recv_exit_status()

    if out_text:
        print(out_text)
    if err_text and ("setting up" in err_text.lower() or "unpacking" in err_text.lower()):
        print(err_text)

    if exit_status != 0:
        print(f"\n{Color.RED}[-] dpkg 安装返回错误码: {exit_status}{Color.RESET}", file=sys.stderr)
        if err_text:
            print(f"{Color.RED}{err_text}{Color.RESET}", file=sys.stderr)
        return False

    print(f"\n{Color.BOLD}{Color.GREEN}🎉 DEB 插件已成功安装到 iPhone!{Color.RESET}")

    # 3. 重载目标进程或 Respring
    if kill_process:
        print(f"{Color.BLUE}[*] 正在重启目标应用进程: {kill_process} ...{Color.RESET}")
        kill_cmd = f"{prefix}killall -9 '{kill_process}' 2>/dev/null || true"
        client.exec_command(kill_cmd)
        print(f"{Color.GREEN}[+] 目标应用 '{kill_process}' 已关闭并重新就绪，在手机上打开即可生效!{Color.RESET}")
    elif respring:
        print(f"{Color.BLUE}[*] 正在注销桌面 (Respring) ...{Color.RESET}")
        respring_cmd = f"""
        if [ -x /var/jb/usr/bin/sbreload ]; then
            {prefix}/var/jb/usr/bin/sbreload
        elif [ -x /usr/bin/sbreload ]; then
            {prefix}/usr/bin/sbreload
        else
            {prefix}killall -9 SpringBoard
        fi
        """
        client.exec_command(respring_cmd)
        print(f"{Color.GREEN}[+] 桌面已重载完成!{Color.RESET}")
    else:
        print(f"{Color.YELLOW}[提示] 插件已安装。请在手机上手动关闭并重新打开目标 App 生效。{Color.RESET}")

    return True


def main():
    default_cfg = load_default_config()

    parser = argparse.ArgumentParser(
        description="通用 iPhone 越狱插件 (deb) USB/SSH 自动化安装工具",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "target",
        help="目标 .deb 文件路径 或 Theos 插件工程目录 (自动寻找 packages/ 下最新 deb)"
    )
    parser.add_argument(
        "-p", "--port",
        dest="port",
        type=int,
        default=default_cfg["port"],
        help=f"SSH 转发端口 (默认: {default_cfg['port']})"
    )
    parser.add_argument(
        "-H", "--host",
        dest="host",
        default=default_cfg["host"],
        help=f"SSH 主机地址 (默认: {default_cfg['host']})"
    )
    parser.add_argument(
        "-u", "--user",
        dest="user",
        default=default_cfg["user"],
        help=f"SSH 用户名 (默认: {default_cfg['user']})"
    )
    parser.add_argument(
        "--password",
        dest="password",
        default=default_cfg["password"],
        help="SSH 登录密码 (默认从 '手机连接信息.txt' 自动获取)"
    )
    parser.add_argument(
        "--respring",
        dest="respring",
        action="store_true",
        default=False,
        help="安装成功后自动注销 SpringBoard 桌面以激活全局插件"
    )
    parser.add_argument(
        "-k", "--kill",
        dest="kill_process",
        default=None,
        help="安装成功后重启指定应用进程 (例如: -k Messenger 或 -k WhatsApp)"
    )
    args = parser.parse_args()

    # 1. 查找并验证本地 deb 文件
    try:
        deb_path = find_target_deb(args.target)
        file_size_kb = os.path.getsize(deb_path) / 1024.0
    except Exception as e:
        print(f"{Color.RED}[-] 错误: {str(e)}{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    deb_filename = os.path.basename(deb_path)

    print("\n" + "=" * 65)
    print(f"{Color.BOLD}{Color.CYAN}       iPhone DEB 插件自动化安装工具 (USB / SSH){Color.RESET}")
    print("=" * 65)
    print(f"  • 本地安装包 : {Color.BOLD}{deb_filename}{Color.RESET} ({file_size_kb:.2f} KB)")
    print(f"  • 文件路径   : {deb_path}")
    print(f"  • 连接端口   : {args.host}:{args.port} (USB 端口转发)")
    print("-" * 65)

    # 2. 智能连接
    print(f"{Color.BLUE}[*] 正在通过 USB 连接 iPhone ...{Color.RESET}")
    client, auth_user, auth_pwd, err = connect_device(args.host, args.port, args.user, args.password)

    if not client:
        print(f"{Color.RED}[-] 连接失败: {err}{Color.RESET}", file=sys.stderr)
        print(f"{Color.YELLOW}[!] 请检查: iproxy 2222 22 端口转发是否正常运行。{Color.RESET}")
        sys.exit(1)

    print(f"{Color.GREEN}[+] 成功以 '{auth_user}' 用户权限建立 USB 连接!{Color.RESET}")

    # 3. 执行安装
    try:
        success = install_deb_package(client, auth_user, auth_pwd, deb_path, kill_process=args.kill_process, respring=args.respring)
        client.close()
        if not success:
            sys.exit(1)
    except Exception as e:
        print(f"{Color.RED}[-] 安装发生异常: {str(e)}{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
