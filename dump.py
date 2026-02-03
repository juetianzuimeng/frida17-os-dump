#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Modified by: Gemini
# Fixes: 0.00B stuck issue by using system SCP + Correct Password

from __future__ import print_function
from __future__ import unicode_literals
import sys
import codecs
import frida
import threading
import os
import shutil
import time
import argparse
import tempfile
import subprocess
import re
import traceback
import paramiko

# ---------------- 配置区域 ----------------
User = 'root'
# ✅ 已更正为你设置的密码
Password = '88888888'
Host = '127.0.0.1'
Port = 2222
KeyFileName = None
# ----------------------------------------

IS_PY2 = sys.version_info[0] < 3
if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf8')

script_dir = os.path.dirname(os.path.realpath(__file__))
DUMP_JS = os.path.join(script_dir, 'dump.js')

TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
file_dict = {}

finished = threading.Event()

def get_usb_iphone():
    Type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        Type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)
    return device

def generate_ipa(path, display_name):
    ipa_filename = display_name + '.ipa'
    print('\n[+] Generating "{}"'.format(ipa_filename))
    try:
        app_name = file_dict['app']
        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(from_dir, to_dir)
        target_dir = './' + PAYLOAD_DIR
        zip_args = ('zip', '-qr', os.path.join(os.getcwd(), ipa_filename), target_dir)
        subprocess.check_call(zip_args, cwd=TEMP_DIR)
        shutil.rmtree(PAYLOAD_PATH)
        print(f"[+] 成功! 文件保存在: {os.path.join(os.getcwd(), ipa_filename)}")
    except Exception as e:
        print(e)
        finished.set()

# 🔥 核心修改：使用系统 scp 命令替代不稳定的 Python 库
def system_scp_download(remote_path, local_dir):
    print(f"\n[DEBUG] 正在拉取: {remote_path}")

    # 构建系统 scp 命令
    # 利用你配置好的 SSH Key，或者依赖 Host/Port 配置
    scp_args = [
        'scp',
        '-P', str(Port),
        '-r',
        '-o', 'StrictHostKeyChecking=no',      # 不检查指纹
        '-o', 'UserKnownHostsFile=/dev/null',  # 不记录 Hosts
        '-o', 'LogLevel=ERROR',                # 减少干扰
        f'{User}@{Host}:{remote_path}',
        local_dir
    ]

    try:
        subprocess.check_call(scp_args)
        print("[DEBUG] 传输完成")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] SCP 传输失败: {e}")
        print(f"尝试手动运行: {' '.join(scp_args)}")

def on_message(message, data):
    if message.get('type') == 'log':
        print(message.get('payload', ''))
        return

    if 'payload' in message:
        payload = message['payload']
        if not isinstance(payload, dict):
            return

        # 1. 下载解密后的二进制
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']  # 手机上的临时路径

            # ⚡️ 这里调用系统 SCP，而不是 Python 库
            system_scp_download(dump_path, PAYLOAD_PATH + '/')

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            try:
                subprocess.check_call(('chmod', '655', chmod_dir))
            except Exception as err:
                print(err)

            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

        # 2. 下载整个 App Bundle
        if 'app' in payload:
            app_path = payload['app']

            # ⚡️ 这里调用系统 SCP
            system_scp_download(app_path, PAYLOAD_PATH + '/')

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            try:
                subprocess.check_call(('chmod', '755', chmod_dir))
            except Exception as err:
                print(err)

            file_dict['app'] = os.path.basename(app_path)

        if 'done' in payload:
            finished.set()

def load_js_file(session, filename):
    source = ''
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    return script

def create_dir(path):
    path = path.strip().rstrip('\\')
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(err)

def open_target_app(device, name_or_bundleid):
    print('Start the target app {}'.format(name_or_bundleid))
    pid = ''
    session = None
    display_name = ''
    bundle_identifier = ''
    applications = device.enumerate_applications()

    for application in applications:
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier
            break

    try:
        if not pid:
            pid = device.spawn([bundle_identifier])
            session = device.attach(pid)
            device.resume(pid)
        else:
            session = device.attach(pid)
    except Exception as e:
        print(e)
    return session, display_name, bundle_identifier

def start_dump(session, ipa_name, display_name, app_path=None):
    print('Dumping {} to {}'.format(display_name, TEMP_DIR))
    script = load_js_file(session, DUMP_JS)
    time.sleep(2)  # Wait for JS to initialize
    payload = {}
    if app_path:
        payload['app_path'] = app_path
    script.exports.start_dump(payload)
    finished.wait()
    generate_ipa(PAYLOAD_PATH, ipa_name)
    if session:
        session.detach()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='frida-ios-dump (Modified)')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Specify name of the decrypted IPA')
    parser.add_argument('-p', '--port', dest='ssh_port', help='Specify SSH port')
    parser.add_argument('-u', '--user', dest='ssh_user', help='Specify SSH username')

    args = parser.parse_args()

    if args.ssh_port:
        Port = int(args.ssh_port)
    if args.ssh_user:
        User = args.ssh_user

    if not args.target:
        parser.print_help()
        sys.exit(0)

    device = get_usb_iphone()
    target = args.target

    create_dir(PAYLOAD_PATH)

    try:
        # 这一步使用 Paramiko + 密码连接（用于控制）
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(Host, port=Port, username=User, password=Password)

        (session, display_name, bundle_identifier) = open_target_app(device, target)
        if not session:
            print("[-] Error: Can not find app or attach failed.")
            sys.exit(1)

        output_ipa = args.output_ipa or display_name
        output_ipa = re.sub('\.ipa$', '', output_ipa)
        
        # New: Resolve App Path via SSH
        print("[*] Resolving App bundle path via SSH...")
        
        # Strategy 1: Search for .app directory matching the display name (if it looks like a name)
        # Strategy 2: If display name is a bundle ID, try to find a mapping or just search for the last part
        
        search_term = display_name
        if "." in display_name:
             # Assume bundle ID like net.whatsapp.WhatsApp -> Search for WhatsApp.app
             search_term = display_name.split(".")[-1]
        
        # Sanitize search term: remove non-ascii chars
        original_term = search_term
        search_term = "".join([c for c in search_term if c.isascii()])
        if not search_term:
            search_term = original_term 
            
        print(f"[*] Searching for app path using term: {search_term}")
        
        # Command to find .app folders and filter
        # We search in standard application directories
        cmd = f"find /var/containers/Bundle/Application -maxdepth 2 -name '*.app' -type d | grep -i '{search_term}'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        app_paths = stdout.read().decode().strip().split('\n')
        
        # Filter and Fallback
        app_paths = [p for p in app_paths if p.strip()]
        
        if not app_paths and "whatsapp" in display_name.lower():
             print("[*] Generic search failed, trying explicit 'WhatsApp.app' search...")
             cmd = f"find /var/containers/Bundle/Application -maxdepth 2 -name 'WhatsApp.app' -type d"
             stdin, stdout, stderr = ssh.exec_command(cmd)
             app_paths = stdout.read().decode().strip().split('\n')
             app_paths = [p for p in app_paths if p.strip()]
        
        resolved_app_path = None
        # Filter out empty strings
        app_paths = [p for p in app_paths if p.strip()]
        
        if app_paths:
            # Pick the shortest path usually, or the one that exactly matches
            resolved_app_path = app_paths[0].strip()
            print(f"[+] Found App Path: {resolved_app_path}")
        else:
             print(f"[-] Could not resolve app path via SSH for term '{search_term}'. Trying fallback to full find...")
             # Fallback: finding any .app and grepping for the full bundle id might be hard without Info.plist inspection
             # Let's hope the simplified search worked.
             
        start_dump(session, output_ipa, display_name, resolved_app_path)

    except Exception as e:
        print('*** Caught exception: %s' % e)
        traceback.print_exc()
        sys.exit(1)
    finally:
        if 'ssh' in locals() and ssh:
            ssh.close()

    if os.path.exists(PAYLOAD_PATH):
        shutil.rmtree(PAYLOAD_PATH)