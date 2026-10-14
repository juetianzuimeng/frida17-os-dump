# -*- coding: utf-8 -*-
"""
Mach-O 原生沙盒特权与签名元数据静态提取器 (Entitlements Extractor)

借鉴 REA (Reverse Engineer Anything) 的 BinaryMetadataProvider 机制：
1. 纯 Python 原生解析 Mach-O 的 LC_CODE_SIGNATURE (0x1D)；
2. 递归解码 SuperBlob (0xFADE0CC0) 并定位 CSSLOT_ENTITLEMENTS (0x5)；
3. 提取完整的 XML / plist 沙盒特权描述文件；
4. 结构化高亮呈现 Keychain Access Groups、App Groups、Associated Domains 与 iCloud 容器等核心机密，
   免去真机环境与 ldid / codesign 外部命令依赖。
"""

import os
import plistlib
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any


# Mach-O 魔数
FAT_MAGIC    = 0xCAFEBABE
FAT_CIGAM    = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
MH_MAGIC_64  = 0xFEEDFACF
MH_CIGAM_64  = 0xCFFAEDFE
MH_MAGIC     = 0xFEEDFACE
MH_CIGAM     = 0xCEFAEDFE
CPU_TYPE_ARM64  = 0x01000000 | 12

# 代码签名相关常数
LC_CODE_SIGNATURE            = 0x1D
CSMAGIC_EMBEDDED_SIGNATURE   = 0xFADE0CC0  # SuperBlob magic
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171 # Entitlements XML blob magic
CSMAGIC_EMBEDDED_ENTITLEMENTS_DER = 0xFADE7172 # Entitlements DER blob magic
CSSLOT_ENTITLEMENTS          = 0x00000005
CSSLOT_ENTITLEMENTS_DER      = 0x00000007


@dataclass
class EntitlementsSummary:
    """特权核心配置摘要"""
    app_id: Optional[str] = None
    team_id: Optional[str] = None
    aps_environment: Optional[str] = None
    keychain_access_groups: List[str] = field(default_factory=list)
    application_groups: List[str] = field(default_factory=list)
    icloud_containers: List[str] = field(default_factory=list)
    associated_domains: List[str] = field(default_factory=list)
    other_entitlements: Dict[str, Any] = field(default_factory=dict)
    raw_xml: str = ""


class EntitlementsExtractor:
    """Mach-O / IPA 原生沙盒特权提取器"""

    def __init__(self, target_path: str):
        self.target_path = os.path.abspath(target_path)
        self.summary: Optional[EntitlementsSummary] = None

    def extract(self) -> Optional[EntitlementsSummary]:
        """提取并解析沙盒特权"""
        if self.summary:
            return self.summary

        if not os.path.exists(self.target_path):
            return None

        # 1. 如果是 IPA 包，定位主可执行文件
        if self.target_path.lower().endswith(".ipa") or zipfile.is_zipfile(self.target_path):
            return self._extract_from_ipa()
        else:
            return self._extract_from_macho_file(self.target_path)

    def _extract_from_ipa(self) -> Optional[EntitlementsSummary]:
        try:
            with zipfile.ZipFile(self.target_path, "r") as zf:
                # 寻找 Payload/*.app/ 下的主 Mach-O 文件
                main_bin_entry = None
                for name in zf.namelist():
                    parts = name.strip("/").split("/")
                    if len(parts) == 3 and parts[0] == "Payload" and parts[1].endswith(".app"):
                        main_bin_entry = name
                        break

                if not main_bin_entry:
                    # 容错匹配任意 app 目录内的顶级文件
                    for name in zf.namelist():
                        if "/Payload/" in f"/{name}" and name.endswith(".app/"):
                            app_dir = name
                            app_name = os.path.splitext(os.path.basename(name.rstrip("/")))[0]
                            candidate = f"{app_dir}{app_name}"
                            if candidate in zf.namelist():
                                main_bin_entry = candidate
                                break

                if not main_bin_entry:
                    return None

                with zf.open(main_bin_entry, "r") as f:
                    bin_data = f.read()
                    return self._parse_macho_bytes(bin_data)
        except Exception:
            return None

    def _extract_from_macho_file(self, file_path: str) -> Optional[EntitlementsSummary]:
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self._parse_macho_bytes(data)
        except Exception:
            return None

    def _parse_macho_bytes(self, data: bytes) -> Optional[EntitlementsSummary]:
        if len(data) < 8:
            return None

        slice_offset = self._find_arm64_slice(data)
        if slice_offset < 0:
            slice_offset = 0

        # 解析 Mach-O 头部和 Load Commands
        if slice_offset + 32 > len(data):
            return None

        le_magic = struct.unpack_from("<I", data, slice_offset)[0]
        is_64 = le_magic in (MH_MAGIC_64, MH_CIGAM_64)
        endian = "<" if le_magic in (MH_MAGIC, MH_MAGIC_64) else ">"
        hdr_size = 32 if is_64 else 28

        if slice_offset + hdr_size > len(data):
            return None

        if is_64:
            _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from(f"{endian}7I", data, slice_offset + 4)
        else:
            _, _, _, ncmds, sizeofcmds, _ = struct.unpack_from(f"{endian}6I", data, slice_offset + 4)

        cmd_pos = slice_offset + hdr_size
        cs_off, cs_sz = None, None

        for _ in range(ncmds):
            if cmd_pos + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(f"{endian}2I", data, cmd_pos)
            if cmdsize == 0:
                break
            if cmd == LC_CODE_SIGNATURE:
                dataoff, datasize = struct.unpack_from(f"{endian}2I", data, cmd_pos + 8)
                cs_off = slice_offset + dataoff
                cs_sz = datasize
                break
            cmd_pos += cmdsize

        if not cs_off or cs_off + 12 > len(data):
            return None

        # 解析 SuperBlob (大端编码)
        sb_magic, sb_len, sb_count = struct.unpack_from(">3I", data, cs_off)
        if sb_magic != CSMAGIC_EMBEDDED_SIGNATURE:
            return None

        idx_pos = cs_off + 12
        xml_bytes = None

        for _ in range(sb_count):
            if idx_pos + 8 > len(data):
                break
            b_type, b_off = struct.unpack_from(">2I", data, idx_pos)
            if b_type == CSSLOT_ENTITLEMENTS:
                blob_pos = cs_off + b_off
                if blob_pos + 8 <= len(data):
                    emagic, elen = struct.unpack_from(">2I", data, blob_pos)
                    if emagic == CSMAGIC_EMBEDDED_ENTITLEMENTS and blob_pos + elen <= len(data):
                        xml_bytes = data[blob_pos + 8 : blob_pos + elen]
                        break
            idx_pos += 8

        if not xml_bytes:
            return None

        try:
            raw_xml = xml_bytes.decode("utf-8", errors="replace")
            ent_dict = plistlib.loads(xml_bytes)
        except Exception:
            return None

        summary = EntitlementsSummary(raw_xml=raw_xml)
        for k, v in ent_dict.items():
            k_lower = k.lower()
            if "application-identifier" in k_lower:
                summary.app_id = str(v)
            elif "team-identifier" in k_lower:
                summary.team_id = str(v)
            elif "aps-environment" in k_lower:
                summary.aps_environment = str(v)
            elif "keychain-access-groups" in k_lower:
                summary.keychain_access_groups = list(v) if isinstance(v, list) else [str(v)]
            elif "application-groups" in k_lower:
                summary.application_groups = list(v) if isinstance(v, list) else [str(v)]
            elif "icloud-container-identifiers" in k_lower or "ubiquity-container-identifiers" in k_lower:
                items = list(v) if isinstance(v, list) else [str(v)]
                for item in items:
                    if item not in summary.icloud_containers:
                        summary.icloud_containers.append(item)
            elif "associated-domains" in k_lower:
                summary.associated_domains = list(v) if isinstance(v, list) else [str(v)]
            else:
                summary.other_entitlements[k] = v

        self.summary = summary
        return summary

    def _find_arm64_slice(self, data: bytes) -> int:
        """寻找 arm64 切片起始偏移"""
        magic = struct.unpack_from(">I", data, 0)[0]
        if magic in (FAT_MAGIC, FAT_CIGAM):
            endian = ">" if magic == FAT_MAGIC else "<"
            nfat = struct.unpack_from(f"{endian}I", data, 4)[0]
            pos = 8
            for _ in range(nfat):
                if pos + 20 > len(data): break
                ct, cs, off, sz, _ = struct.unpack_from(f"{endian}5I", data, pos)
                if ct == CPU_TYPE_ARM64: return off
                pos += 20
        elif magic in (FAT_MAGIC_64, FAT_CIGAM_64):
            endian = ">" if magic == FAT_MAGIC_64 else "<"
            nfat = struct.unpack_from(f"{endian}I", data, 4)[0]
            pos = 8
            for _ in range(nfat):
                if pos + 32 > len(data): break
                ct, cs, off, sz, _ = struct.unpack_from(f"{endian}2I2QI", data, pos)
                if ct == CPU_TYPE_ARM64: return off
                pos += 32
        return 0
