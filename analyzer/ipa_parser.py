# -*- coding: utf-8 -*-
"""
IPA 包与应用资产解析器 (IPA Parser)
负责解压与定位 Payload、解析 Info.plist、embedded.mobileprovision、Frameworks 动态库以及证书资产
"""

import os
import plistlib
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from .rules.base import TargetBinaryInfo
from .macho_parser import MachOParser


@dataclass
class CertificateAsset:
    file_name: str
    rel_path: str
    abs_path: str
    size_bytes: int


@dataclass
class AppPackageInfo:
    ipa_path: str
    app_dir: str                  # Payload/AppName.app 的绝对路径
    temp_dir: Optional[str] = None # 若为解压临时目录则记录用于清理
    bundle_id: str = ""
    bundle_name: str = ""
    bundle_version: str = ""
    display_name: str = ""
    min_os_version: str = ""
    executable_name: str = ""
    info_plist_raw: Dict[str, Any] = field(default_factory=dict)
    url_schemes: List[str] = field(default_factory=list)
    ats_settings: Dict[str, Any] = field(default_factory=dict)
    entitlements: Dict[str, Any] = field(default_factory=dict)
    
    # 扫描到的各类二进制文件
    main_binary: Optional[TargetBinaryInfo] = None
    frameworks: List[TargetBinaryInfo] = field(default_factory=list)
    plugins: List[TargetBinaryInfo] = field(default_factory=list)
    
    # 提取到的证书资产
    certificates: List[CertificateAsset] = field(default_factory=list)


class IPAParser:
    """IPA 与 App 目录分析提取器"""

    def __init__(self, target_path: str):
        self.target_path = os.path.abspath(target_path)
        self.temp_dir: Optional[str] = None

    def parse(self) -> AppPackageInfo:
        """主解析入口"""
        if not os.path.exists(self.target_path):
            raise FileNotFoundError(f"目标文件不存在: {self.target_path}")

        app_dir = ""
        if os.path.isdir(self.target_path):
            # 直接传入了 .app 目录
            if self.target_path.endswith(".app"):
                app_dir = self.target_path
            else:
                # 检查子目录中是否有 Payload/*.app
                payload_dir = os.path.join(self.target_path, "Payload")
                if os.path.exists(payload_dir):
                    app_dir = self._find_app_in_payload(payload_dir)
                else:
                    app_dir = self.target_path
        else:
            # 传入了 .ipa 文件，解压到临时目录
            self.temp_dir = tempfile.mkdtemp(prefix="ipa_analyze_")
            self._extract_ipa(self.target_path, self.temp_dir)
            payload_dir = os.path.join(self.temp_dir, "Payload")
            app_dir = self._find_app_in_payload(payload_dir)

        if not app_dir or not os.path.exists(app_dir):
            raise ValueError(f"无法在 IPA 包内找到有效的 Payload/*.app 目录: {self.target_path}")

        pkg_info = AppPackageInfo(
            ipa_path=self.target_path,
            app_dir=app_dir,
            temp_dir=self.temp_dir
        )

        # 1. 解析 Info.plist
        self._parse_info_plist(pkg_info)

        # 2. 解析 embedded.mobileprovision
        self._parse_provisioning_profile(pkg_info)

        # 3. 收集证书等安全敏感资源
        self._collect_security_assets(pkg_info)

        # 4. 定位并解析所有 Mach-O 二进制（主二进制、Frameworks、PlugIns）
        self._collect_and_parse_binaries(pkg_info)

        return pkg_info

    def cleanup(self):
        """清理临时解压目录"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None

    def _extract_ipa(self, ipa_file: str, extract_to: str):
        """解压 IPA 文件"""
        with zipfile.ZipFile(ipa_file, "r") as zf:
            zf.extractall(extract_to)

    def _find_app_in_payload(self, payload_dir: str) -> str:
        """在 Payload 目录中查找 .app 文件夹"""
        if not os.path.exists(payload_dir):
            return ""
        for name in os.listdir(payload_dir):
            if name.endswith(".app"):
                return os.path.join(payload_dir, name)
        return ""

    def _parse_info_plist(self, pkg_info: AppPackageInfo):
        """解析 Info.plist 配置"""
        plist_path = os.path.join(pkg_info.app_dir, "Info.plist")
        if not os.path.exists(plist_path):
            return

        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
            pkg_info.info_plist_raw = data
            pkg_info.bundle_id = str(data.get("CFBundleIdentifier", ""))
            pkg_info.bundle_name = str(data.get("CFBundleName", ""))
            pkg_info.display_name = str(data.get("CFBundleDisplayName", pkg_info.bundle_name))
            pkg_info.bundle_version = str(data.get("CFBundleShortVersionString", data.get("CFBundleVersion", "")))
            pkg_info.min_os_version = str(data.get("MinimumOSVersion", ""))
            pkg_info.executable_name = str(data.get("CFBundleExecutable", ""))

            # 提取 URL Schemes
            url_types = data.get("CFBundleURLTypes", [])
            if isinstance(url_types, list):
                for item in url_types:
                    if isinstance(item, dict):
                        schemes = item.get("CFBundleURLSchemes", [])
                        if isinstance(schemes, list):
                            for s in schemes:
                                if s and s not in pkg_info.url_schemes:
                                    pkg_info.url_schemes.append(str(s))

            # 提取 ATS 配置
            ats = data.get("NSAppTransportSecurity", {})
            if isinstance(ats, dict):
                pkg_info.ats_settings = ats
        except Exception:
            pass

    def _parse_provisioning_profile(self, pkg_info: AppPackageInfo):
        """解析 embedded.mobileprovision 获取 Entitlements 权限"""
        prov_path = os.path.join(pkg_info.app_dir, "embedded.mobileprovision")
        if not os.path.exists(prov_path):
            return

        try:
            with open(prov_path, "rb") as f:
                content = f.read()

            start = content.find(b"<?xml")
            end = content.find(b"</plist>")
            if start != -1 and end != -1:
                plist_xml = content[start : end + 8]
                plist_data = plistlib.loads(plist_xml)
                pkg_info.entitlements = plist_data.get("Entitlements", {})
        except Exception:
            pass

    def _collect_security_assets(self, pkg_info: AppPackageInfo):
        """收集包内的证书与密钥文件"""
        cert_exts = {".cer", ".crt", ".der", ".pem", ".p12", ".pfx"}
        for root, _, files in os.walk(pkg_info.app_dir):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() in cert_exts:
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, pkg_info.app_dir)
                    pkg_info.certificates.append(
                        CertificateAsset(
                            file_name=file,
                            rel_path=rel_p,
                            abs_path=full_p,
                            size_bytes=os.path.getsize(full_p)
                        )
                    )

    def _collect_and_parse_binaries(self, pkg_info: AppPackageInfo):
        """发现并解析所有 Mach-O 二进制文件"""
        # 1. 主二进制
        main_exec_name = pkg_info.executable_name or pkg_info.bundle_name
        main_exec_path = os.path.join(pkg_info.app_dir, main_exec_name) if main_exec_name else ""

        if main_exec_path and os.path.isfile(main_exec_path):
            main_parser = MachOParser(
                file_path=main_exec_path,
                rel_path=main_exec_name,
                is_main=True
            )
            pkg_info.main_binary = main_parser.parse()

        # 2. Frameworks 目录
        frameworks_dir = os.path.join(pkg_info.app_dir, "Frameworks")
        if os.path.isdir(frameworks_dir):
            for item in os.listdir(frameworks_dir):
                item_path = os.path.join(frameworks_dir, item)
                if item.endswith(".framework") and os.path.isdir(item_path):
                    # 获取 framework 内部同名 Mach-O
                    fw_name = os.path.splitext(item)[0]
                    fw_exec = os.path.join(item_path, fw_name)
                    if os.path.isfile(fw_exec):
                        fw_rel = os.path.relpath(fw_exec, pkg_info.app_dir)
                        fw_parser = MachOParser(
                            file_path=fw_exec,
                            rel_path=fw_rel,
                            is_framework=True
                        )
                        pkg_info.frameworks.append(fw_parser.parse())
                elif item.endswith(".dylib") and os.path.isfile(item_path):
                    dylib_rel = os.path.relpath(item_path, pkg_info.app_dir)
                    dylib_parser = MachOParser(
                        file_path=item_path,
                        rel_path=dylib_rel,
                        is_framework=True
                    )
                    pkg_info.frameworks.append(dylib_parser.parse())

        # 3. PlugIns 目录 (App Extensions)
        plugins_dir = os.path.join(pkg_info.app_dir, "PlugIns")
        if os.path.isdir(plugins_dir):
            for item in os.listdir(plugins_dir):
                item_path = os.path.join(plugins_dir, item)
                if item.endswith(".appex") and os.path.isdir(item_path):
                    plug_name = os.path.splitext(item)[0]
                    plug_exec = os.path.join(item_path, plug_name)
                    if os.path.isfile(plug_exec):
                        plug_rel = os.path.relpath(plug_exec, pkg_info.app_dir)
                        plug_parser = MachOParser(
                            file_path=plug_exec,
                            rel_path=plug_rel,
                            is_plugin=True
                        )
                        pkg_info.plugins.append(plug_parser.parse())
