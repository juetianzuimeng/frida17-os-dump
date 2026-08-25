#!/usr/bin/env python
# -*- coding: utf-8 -*-

# frida-ios-dump (USB Mode)
# 通过 Frida USB 直连传输文件，无需 SSH/SCP

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

CHUNK_SIZE = 512 * 1024  # 512KB per chunk


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


def frida_download_file(script, remote_path, local_path):
    """通过 Frida RPC 从设备下载单个文件"""
    try:
        file_size = script.exports_sync.get_file_size(remote_path)
        if file_size is None or file_size < 0:
            print(f"  [WARN] 无法获取文件大小: {remote_path}")
            return False

        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        downloaded = 0
        with open(local_path, 'wb') as f:
            offset = 0
            while offset < file_size:
                chunk_size = min(CHUNK_SIZE, file_size - offset)
                data = script.exports_sync.read_file_chunk(remote_path, offset, chunk_size)
                if data is None or len(data) == 0:
                    break
                f.write(data)
                offset += len(data)
                downloaded += len(data)

        if downloaded > 0:
            print(f"  [USB] ✓ {os.path.basename(remote_path)} ({downloaded:,} bytes)")
        return True
    except Exception as e:
        print(f"  [ERROR] 下载文件失败 {remote_path}: {e}")
        return False


def frida_download_dir(script, remote_dir, local_dir):
    """通过 Frida RPC 从设备下载整个目录"""
    try:
        files = script.exports_sync.list_files(remote_dir)
        if not files:
            print(f"  [WARN] 目录为空或无法列出: {remote_dir}")
            return False

        dir_name = os.path.basename(remote_dir)
        print(f"\n[USB] 正在下载 App Bundle: {dir_name} ({len(files)} 个文件)")
        os.makedirs(local_dir, exist_ok=True)

        for i, remote_file in enumerate(files):
            # 计算相对路径
            rel_path = remote_file[len(remote_dir):]
            if rel_path.startswith('/'):
                rel_path = rel_path[1:]
            local_file = os.path.join(local_dir, rel_path)
            frida_download_file(script, remote_file, local_file)
            # 进度提示
            if (i + 1) % 50 == 0:
                print(f"  [USB] 进度: {i + 1}/{len(files)}")

        print(f"[USB] App Bundle 下载完成: {dir_name}")
        return True
    except Exception as e:
        print(f"[ERROR] 下载目录失败 {remote_dir}: {e}")
        traceback.print_exc()
        return False


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


def on_message(message, data):
    """仅用于接收 console.log 输出"""
    if message.get('type') == 'log':
        print(message.get('payload', ''))
    elif message.get('type') == 'error':
        desc = message.get('description', '')
        stack = message.get('stack', '')
        filename = message.get('fileName', '')
        lineno = message.get('lineNumber', '')
        print(f"[JS Error] {desc}")
        if filename or lineno:
            print(f"  at {filename}:{lineno}")
        if stack:
            print(f"  Stack: {stack}")


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


def start_dump(session, ipa_name, display_name):
    global file_dict
    file_dict = {}

    print('Dumping {} to {}'.format(display_name, TEMP_DIR))
    script = load_js_file(session, DUMP_JS)
    time.sleep(2)  # Wait for JS to initialize

    # 启动砸壳 - JS 侧会自行解析 app_path 并通过 return 返回结果
    print("[*] 开始砸壳...")
    result = script.exports_sync.start_dump({})

    if not result or not result.get('appPath'):
        print("[-] 砸壳失败: 无法解析 App 路径")
        if session:
            session.detach()
        return

    app_path = result['appPath']
    dump_modules = result.get('modules', [])
    print(f"\n[+] App 路径: {app_path}")
    print(f"[+] 已砸壳模块数: {len(dump_modules)}")

    # 通过 Frida USB 下载所有文件
    print(f"\n{'='*50}")
    print(f"[USB] 开始通过 USB 传输文件...")
    print(f"{'='*50}")

    # 1. 下载解密后的 .fid 模块
    for mod in dump_modules:
        dump_path = mod.get('dump')
        origin_path = mod.get('path')
        if not dump_path:
            continue

        local_name = os.path.basename(dump_path)
        local_path = os.path.join(PAYLOAD_PATH, local_name)
        frida_download_file(script, dump_path, local_path)
        try:
            subprocess.check_call(('chmod', '655', local_path))
        except Exception:
            pass

        if origin_path:
            index = origin_path.find('.app/')
            if index != -1:
                file_dict[local_name] = origin_path[index + 5:]

    # 2. 下载整个 App Bundle
    local_app_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
    frida_download_dir(script, app_path, local_app_dir)
    try:
        subprocess.check_call(('chmod', '755', local_app_dir))
    except Exception:
        pass
    file_dict['app'] = os.path.basename(app_path)

    print(f"\n{'='*50}")
    print(f"[USB] 文件传输完成")
    print(f"{'='*50}\n")

    generate_ipa(PAYLOAD_PATH, ipa_name)

    if session:
        session.detach()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='frida-ios-dump (USB Mode - No SSH Required)')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Specify name of the decrypted IPA')
    parser.add_argument('-l', '--list', dest='list_apps', action='store_true', help='List installed applications')

    args = parser.parse_args()

    device = get_usb_iphone()
    print(f"[*] Connected to: {device.name} ({device.id})")

    if args.list_apps:
        print("\n[*] Installed Applications:")
        apps = device.enumerate_applications()
        running = [a for a in apps if a.pid > 0]
        installed = [a for a in apps if a.pid == 0]

        if running:
            print("\n  Running:")
            for app in sorted(running, key=lambda a: a.name):
                print(f"    PID {app.pid:>5}  {app.name} ({app.identifier})")

        if installed:
            print(f"\n  Installed ({len(installed)} apps):")
            for app in sorted(installed, key=lambda a: a.name):
                print(f"    {app.name} ({app.identifier})")
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(0)

    target = args.target

    create_dir(PAYLOAD_PATH)

    try:
        (session, display_name, bundle_identifier) = open_target_app(device, target)
        if not session:
            print("[-] Error: Can not find app or attach failed.")
            sys.exit(1)

        output_ipa = args.output_ipa or display_name
        output_ipa = re.sub('\\.ipa$', '', output_ipa)

        start_dump(session, output_ipa, display_name)

    except Exception as e:
        print('*** Caught exception: %s' % e)
        traceback.print_exc()
        sys.exit(1)

    if os.path.exists(PAYLOAD_PATH):
        shutil.rmtree(PAYLOAD_PATH)