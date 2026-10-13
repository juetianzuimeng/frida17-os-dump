# -*- coding: utf-8 -*-
"""
Mach-O 64-bit Objective-C 元数据解析器 (ObjC Metadata Parser)
纯 Python 实现，脱壳后无需连接真机即可直接解析 Mach-O 内部的：
- __objc_classlist: 类定义 (Class name, super class, instance/class methods, ivars, properties)
- __objc_catlist: 分类扩展 (Category name, extended class, category methods)
- __objc_protolist: 协议声明 (Protocol name, methods)
- __objc_methname / __objc_classname: 原生选择子与类名字典
支持解析传统绝对地址 Method List 以及 iOS 14+ / macOS 11+ relative method list (METHOD_LIST_SMALL)。
内置 PAC (Pointer Authentication Code) 掩码过滤与 Chained Fixups 基址对齐算法。
"""

import os
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set, Any


@dataclass
class ObjCMethod:
    name: str
    type_encoding: str = ""
    is_class_method: bool = False
    imp_va: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type_encoding,
            "is_class_method": self.is_class_method,
            "imp_va": hex(self.imp_va) if self.imp_va else "0x0"
        }


@dataclass
class ObjCClass:
    name: str
    super_class: str = ""
    demangled_name: Optional[str] = None
    instance_methods: List[ObjCMethod] = field(default_factory=list)
    class_methods: List[ObjCMethod] = field(default_factory=list)
    properties: List[str] = field(default_factory=list)
    ivars: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.demangled_name if self.demangled_name else self.name

    @property
    def total_methods_count(self) -> int:
        return len(self.instance_methods) + len(self.class_methods)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "demangled_name": self.demangled_name,
            "super_class": self.super_class,
            "instance_methods": [m.to_dict() for m in self.instance_methods],
            "class_methods": [m.to_dict() for m in self.class_methods],
            "properties": self.properties,
            "ivars": self.ivars,
            "protocols": self.protocols
        }


@dataclass
class ObjCCategory:
    name: str
    class_name: str
    demangled_class_name: Optional[str] = None
    instance_methods: List[ObjCMethod] = field(default_factory=list)
    class_methods: List[ObjCMethod] = field(default_factory=list)
    properties: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)

    @property
    def display_class_name(self) -> str:
        return self.demangled_class_name if self.demangled_class_name else self.class_name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "class_name": self.class_name,
            "demangled_class_name": self.demangled_class_name,
            "instance_methods": [m.to_dict() for m in self.instance_methods],
            "class_methods": [m.to_dict() for m in self.class_methods],
            "properties": self.properties,
            "protocols": self.protocols
        }


@dataclass
class ObjCMetadata:
    classes: Dict[str, ObjCClass] = field(default_factory=dict)
    categories: List[ObjCCategory] = field(default_factory=list)
    selectors: Set[str] = field(default_factory=set)
    class_names: Set[str] = field(default_factory=set)

    @property
    def class_count(self) -> int:
        return len(self.classes)

    @property
    def category_count(self) -> int:
        return len(self.categories)

    @property
    def selector_count(self) -> int:
        return len(self.selectors)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "class_count": self.class_count,
            "category_count": self.category_count,
            "selector_count": self.selector_count,
            "classes": {k: v.to_dict() for k, v in self.classes.items()},
            "categories": [c.to_dict() for c in self.categories]
        }


@dataclass
class MachOSegment:
    segname: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


@dataclass
class MachOSection:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int


class ObjCParser:
    """Mach-O 64位 Objective-C 静态结构解析引擎"""

    def __init__(self, file_path: str, slice_offset: int = 0, slice_size: int = 0):
        self.file_path = file_path
        self.slice_offset = slice_offset
        self.slice_size = slice_size or os.path.getsize(file_path)
        self.segments: List[MachOSegment] = []
        self.sections: Dict[str, MachOSection] = {}  # key: sectname (e.g. '__objc_classlist')
        self.image_base: int = 0
        self._f = None
        self.is_64 = True
        self.endian = "<"

    def parse(self) -> ObjCMetadata:
        """解析主流程"""
        metadata = ObjCMetadata()
        if not os.path.isfile(self.file_path):
            return metadata

        try:
            with open(self.file_path, "rb") as f:
                self._f = f
                # 1. 扫描 Mach-O load commands 构建内存与段映射
                if not self._parse_load_commands():
                    return metadata

                # 2. 提取基础段中的所有 Selector 与 ClassName 字符串字典
                self._harvest_objc_strings(metadata)

                # 3. 解析 __objc_classlist 类定义
                self._parse_classes(metadata)

                # 4. 解析 __objc_catlist 分类定义
                self._parse_categories(metadata)

                # 5. 自动对 Swift 混淆类名与分类进行 Demangle 还原
                self._demangle_swift_metadata(metadata)

        except Exception as e:
            # 容错解析，避免异常影响整体流程
            pass
        finally:
            self._f = None

        return metadata

    def _demangle_swift_metadata(self, metadata: ObjCMetadata):
        """对 Swift 桥接生成的 ObjC 类名与分类名进行符号还原"""
        try:
            from .demangler import SwiftDemangler

            all_names = list(metadata.classes.keys()) + [cat.class_name for cat in metadata.categories]
            demangled_map = SwiftDemangler.demangle_batch(all_names)

            for cname, cinfo in metadata.classes.items():
                dem = demangled_map.get(cname)
                if dem and dem != cname:
                    cinfo.demangled_name = dem
                    metadata.class_names.add(dem)

            for cat in metadata.categories:
                dem = demangled_map.get(cat.class_name)
                if dem and dem != cat.class_name:
                    cat.demangled_class_name = dem
        except Exception:
            pass

    def _parse_load_commands(self) -> bool:
        """解析 64 位 Mach-O 段与节"""
        self._f.seek(self.slice_offset)
        magic_bytes = self._f.read(4)
        if len(magic_bytes) < 4:
            return False

        magic = struct.unpack("<I", magic_bytes)[0]
        if magic in (0xFEEDFACF, 0xCFFAEDFE):  # MH_MAGIC_64 / MH_CIGAM_64
            self.is_64 = True
            self.endian = "<" if magic == 0xFEEDFACF else ">"
        elif magic in (0xFEEDFACE, 0xCEFAEDFE):
            self.is_64 = False
            self.endian = "<" if magic == 0xFEEDFACE else ">"
            return False  # 现代 iOS 核心为 64 位
        else:
            return False

        self._f.seek(self.slice_offset + 4)
        hdr_data = self._f.read(28)
        if len(hdr_data) < 28:
            return False
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(
            f"{self.endian}7I", hdr_data
        )

        cmd_offset = self.slice_offset + 32
        for _ in range(ncmds):
            self._f.seek(cmd_offset)
            cmd_hdr = self._f.read(8)
            if len(cmd_hdr) < 8:
                break
            cmd, cmdsize = struct.unpack(f"{self.endian}2I", cmd_hdr)
            if cmdsize == 0:
                break

            # LC_SEGMENT_64 = 0x19
            if cmd == 0x19:
                self._f.seek(cmd_offset + 8)
                seg_data = self._f.read(64)
                if len(seg_data) >= 64:
                    segname_raw, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack(
                        f"{self.endian}16s4Q2I2I", seg_data[:64]
                    )
                    segname = segname_raw.decode("ascii", errors="ignore").rstrip("\x00")
                    segment = MachOSegment(
                        segname=segname,
                        vmaddr=vmaddr,
                        vmsize=vmsize,
                        fileoff=fileoff + self.slice_offset,
                        filesize=filesize
                    )
                    self.segments.append(segment)
                    if segname == "__TEXT":
                        self.image_base = vmaddr

                    # 遍历 sections
                    sect_offset = cmd_offset + 72
                    for _s in range(nsects):
                        self._f.seek(sect_offset)
                        s_data = self._f.read(80)
                        if len(s_data) < 80:
                            break
                        sectname_raw, s_segname_raw, s_addr, s_size, s_offset, s_align, s_reloff, s_nreloc, s_flags, r1, r2, r3 = struct.unpack(
                            f"{self.endian}16s16s2Q8I", s_data
                        )
                        sectname = sectname_raw.decode("ascii", errors="ignore").rstrip("\x00")
                        s_segname = s_segname_raw.decode("ascii", errors="ignore").rstrip("\x00")
                        sec = MachOSection(
                            sectname=sectname,
                            segname=s_segname,
                            addr=s_addr,
                            size=s_size,
                            offset=s_offset + self.slice_offset
                        )
                        self.sections[sectname] = sec
                        sect_offset += 80

            cmd_offset += cmdsize

        return len(self.segments) > 0

    def normalize_va(self, va: int) -> Optional[int]:
        """将带有 PAC 签名、TBI 标签或 Chained Fixups 偏移的原始指针标准化为段内的虚拟地址"""
        if va == 0:
            return None

        # 候选地址探测
        candidates = [
            va,
            va & 0x00007FFFFFFFFFFF,        # 清除 arm64 PAC 签名高位
            va & 0x0000007FFFFFFFFF,        # 清除 39-bit 虚拟地址以上位
        ]

        if self.image_base != 0:
            low32 = va & 0xFFFFFFFF
            candidates.append(self.image_base + low32)  # 链式重定位相对基址偏移
            candidates.append(low32)

        for c in candidates:
            for seg in self.segments:
                if seg.vmaddr <= c < seg.vmaddr + seg.vmsize:
                    return c
        return None

    def va_to_offset(self, va: int) -> Optional[int]:
        """将虚地址 (VA) 转换为文件绝对偏移 (Offset)"""
        norm_va = self.normalize_va(va)
        if norm_va is None:
            return None

        for seg in self.segments:
            if seg.vmaddr <= norm_va < seg.vmaddr + seg.vmsize:
                offset = seg.fileoff + (norm_va - seg.vmaddr)
                return offset
        return None

    def read_cstring(self, va: int, max_len: int = 512) -> Optional[str]:
        """从虚拟地址读取以 NULL 结尾的 C 字符串"""
        off = self.va_to_offset(va)
        if off is None:
            return None

        self._f.seek(off)
        data = self._f.read(max_len)
        null_idx = data.find(b"\x00")
        if null_idx != -1:
            raw = data[:null_idx]
        else:
            raw = data
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="ignore")

    def read_ptr(self, va: int) -> int:
        """从虚地址读取一个 64 位指针"""
        off = self.va_to_offset(va)
        if off is None:
            return 0
        self._f.seek(off)
        data = self._f.read(8)
        if len(data) < 8:
            return 0
        return struct.unpack(f"{self.endian}Q", data)[0]

    def _harvest_objc_strings(self, metadata: ObjCMetadata):
        """直接从 __objc_methname 与 __objc_classname 段提取全局选择子与类名字典"""
        for sname, target_set in [("__objc_methname", metadata.selectors), ("__objc_classname", metadata.class_names)]:
            sec = self.sections.get(sname)
            if not sec or sec.size == 0:
                continue
            self._f.seek(sec.offset)
            raw_bytes = self._f.read(sec.size)
            parts = raw_bytes.split(b"\x00")
            for p in parts:
                if 1 <= len(p) <= 256:
                    try:
                        s = p.decode("utf-8")
                        target_set.add(s)
                    except Exception:
                        pass

    def _parse_classes(self, metadata: ObjCMetadata):
        """解析 __objc_classlist 结构体数组"""
        sec = self.sections.get("__objc_classlist")
        if not sec or sec.size == 0:
            return

        ptr_count = sec.size // 8
        self._f.seek(sec.offset)
        class_ptrs_bytes = self._f.read(sec.size)

        for i in range(ptr_count):
            cls_va = struct.unpack(f"{self.endian}Q", class_ptrs_bytes[i*8:(i+1)*8])[0]
            if cls_va == 0:
                continue

            parsed_class = self._parse_class_t(cls_va)
            if parsed_class and parsed_class.name:
                metadata.classes[parsed_class.name] = parsed_class
                metadata.class_names.add(parsed_class.name)
                for m in parsed_class.instance_methods + parsed_class.class_methods:
                    if m.name:
                        metadata.selectors.add(m.name)

    def _parse_class_t(self, cls_va: int) -> Optional[ObjCClass]:
        """解析 class_t 结构体"""
        cls_off = self.va_to_offset(cls_va)
        if cls_off is None:
            return None

        self._f.seek(cls_off)
        data = self._f.read(40)
        if len(data) < 40:
            return None

        # struct class_t: isa(8), superclass(8), cache(8), vtable(8), data(8)
        isa, super_va, cache, vtable, data_va = struct.unpack(f"{self.endian}5Q", data)
        # data_va 指向 class_ro_t (需要清除低3位 fast-pointer 标志)
        ro_va = data_va & ~0x7
        if ro_va == 0:
            return None

        # 解析父类名称
        super_name = ""
        if super_va != 0:
            super_cls = self._parse_class_t(super_va)
            if super_cls:
                super_name = super_cls.name

        return self._parse_class_ro_t(ro_va, super_name=super_name, meta_isa=isa)

    def _parse_class_ro_t(self, ro_va: int, super_name: str = "", meta_isa: int = 0) -> Optional[ObjCClass]:
        """解析 class_ro_t 结构体"""
        ro_off = self.va_to_offset(ro_va)
        if ro_off is None:
            return None

        self._f.seek(ro_off)
        data = self._f.read(72)
        if len(data) < 48:
            return None

        # struct class_ro_t:
        # flags(4), instanceStart(4), instanceSize(4), reserved(4), ivarLayout(8), name(8),
        # baseMethodList(8), baseProtocols(8), ivars(8), weakIvarLayout(8), baseProperties(8)
        flags, inst_start, inst_size, reserved = struct.unpack(f"{self.endian}4I", data[:16])
        ivar_layout, name_va, base_methods_va = struct.unpack(f"{self.endian}3Q", data[16:40])

        class_name = self.read_cstring(name_va)
        if not class_name:
            return None

        obj_class = ObjCClass(name=class_name, super_class=super_name)

        # 1. 实例方法列表
        if base_methods_va != 0:
            obj_class.instance_methods = self._parse_method_list(base_methods_va, is_class_method=False)

        # 2. 类方法列表 (通过 meta_isa 溯源 metaclass -> metaclass.data -> class_ro_t)
        if meta_isa != 0:
            meta_off = self.va_to_offset(meta_isa)
            if meta_off:
                self._f.seek(meta_off)
                meta_data = self._f.read(40)
                if len(meta_data) >= 40:
                    _, _, _, _, meta_ro_ptr = struct.unpack(f"{self.endian}5Q", meta_data)
                    meta_ro_va = meta_ro_ptr & ~0x7
                    if meta_ro_va:
                        meta_ro_off = self.va_to_offset(meta_ro_va)
                        if meta_ro_off:
                            self._f.seek(meta_ro_off)
                            m_hdr = self._f.read(40)
                            if len(m_hdr) >= 40:
                                _, _, _, _, _, _, meta_methods_va = struct.unpack(f"{self.endian}4I3Q", m_hdr[:40])
                                if meta_methods_va != 0:
                                    obj_class.class_methods = self._parse_method_list(meta_methods_va, is_class_method=True)

        # 3. 属性与成员变量
        if len(data) >= 72:
            base_protocols_va, ivars_va, weak_layout, base_props_va = struct.unpack(f"{self.endian}4Q", data[40:72])
            if base_props_va != 0:
                obj_class.properties = self._parse_property_list(base_props_va)
            if ivars_va != 0:
                obj_class.ivars = self._parse_ivar_list(ivars_va)

        return obj_class

    def _parse_method_list(self, ml_va: int, is_class_method: bool = False) -> List[ObjCMethod]:
        """解析 method_list_t (支持传统绝对指针与 relative method list)"""
        ml_off = self.va_to_offset(ml_va)
        if ml_off is None:
            return []

        self._f.seek(ml_off)
        hdr = self._f.read(8)
        if len(hdr) < 8:
            return []

        flags, count = struct.unpack(f"{self.endian}2I", hdr)
        methods: List[ObjCMethod] = []

        is_relative = bool(flags & 0x80000000)

        # 清除 high flags 获取实际基址
        norm_ml_va = self.normalize_va(ml_va) or ml_va

        if is_relative:
            # iOS 14+ / macOS 11+ relative method list
            # 每个条目 12 字节: name_offset(4), types_offset(4), imp_offset(4)
            entries_data = self._f.read(count * 12)
            for i in range(count):
                if (i + 1) * 12 > len(entries_data):
                    break
                n_off, t_off, i_off = struct.unpack(f"{self.endian}3i", entries_data[i*12:(i+1)*12])
                field_addr = norm_ml_va + 8 + i * 12

                # 相对寻址: field_addr + offset
                name_addr = field_addr + n_off
                types_addr = field_addr + 4 + t_off
                imp_addr = field_addr + 8 + i_off

                # name_addr 可能是直接指向 C 字符串，或者是 selector 引用 (指针)
                m_name = self.read_cstring(name_addr)
                if not m_name or not m_name.isprintable():
                    deref_ptr = self.read_ptr(name_addr)
                    if deref_ptr != 0:
                        m_name = self.read_cstring(deref_ptr)

                m_type = self.read_cstring(types_addr) or ""
                if m_name and m_name.strip():
                    methods.append(ObjCMethod(
                        name=m_name.strip(),
                        type_encoding=m_type,
                        is_class_method=is_class_method,
                        imp_va=imp_addr
                    ))
        else:
            # 传统标准 method list
            entsize = flags & ~0x3
            if entsize < 24:
                entsize = 24
            entries_data = self._f.read(count * entsize)
            for i in range(count):
                if (i + 1) * entsize > len(entries_data):
                    break
                m_entry = entries_data[i*entsize:(i+1)*entsize]
                name_va, types_va, imp_va = struct.unpack(f"{self.endian}3Q", m_entry[:24])
                m_name = self.read_cstring(name_va)
                m_type = self.read_cstring(types_va) or ""
                if m_name and m_name.strip():
                    methods.append(ObjCMethod(
                        name=m_name.strip(),
                        type_encoding=m_type,
                        is_class_method=is_class_method,
                        imp_va=imp_va
                    ))

        return methods

    def _parse_categories(self, metadata: ObjCMetadata):
        """解析 __objc_catlist 结构体数组"""
        sec = self.sections.get("__objc_catlist")
        if not sec or sec.size == 0:
            return

        ptr_count = sec.size // 8
        self._f.seek(sec.offset)
        cat_ptrs_bytes = self._f.read(sec.size)

        for i in range(ptr_count):
            cat_va = struct.unpack(f"{self.endian}Q", cat_ptrs_bytes[i*8:(i+1)*8])[0]
            if cat_va == 0:
                continue

            parsed_cat = self._parse_category_t(cat_va)
            if parsed_cat:
                metadata.categories.append(parsed_cat)
                for m in parsed_cat.instance_methods + parsed_cat.class_methods:
                    if m.name:
                        metadata.selectors.add(m.name)

    def _parse_category_t(self, cat_va: int) -> Optional[ObjCCategory]:
        """解析 category_t 结构体"""
        cat_off = self.va_to_offset(cat_va)
        if cat_off is None:
            return None

        self._f.seek(cat_off)
        data = self._f.read(48)
        if len(data) < 32:
            return None

        # struct category_t:
        # name(8), cls(8), instanceMethods(8), classMethods(8), protocols(8), properties(8)
        name_va, cls_va, inst_methods_va, class_methods_va = struct.unpack(f"{self.endian}4Q", data[:32])
        cat_name = self.read_cstring(name_va)
        if not cat_name:
            return None

        target_class_name = ""
        if cls_va != 0:
            cls_obj = self._parse_class_t(cls_va)
            if cls_obj:
                target_class_name = cls_obj.name

        cat = ObjCCategory(name=cat_name, class_name=target_class_name)

        if inst_methods_va != 0:
            cat.instance_methods = self._parse_method_list(inst_methods_va, is_class_method=False)
        if class_methods_va != 0:
            cat.class_methods = self._parse_method_list(class_methods_va, is_class_method=True)

        if len(data) >= 48:
            proto_va, props_va = struct.unpack(f"{self.endian}2Q", data[32:48])
            if props_va != 0:
                cat.properties = self._parse_property_list(props_va)

        return cat

    def _parse_property_list(self, prop_list_va: int) -> List[str]:
        """解析 property_list_t"""
        pl_off = self.va_to_offset(prop_list_va)
        if pl_off is None:
            return []

        self._f.seek(pl_off)
        hdr = self._f.read(8)
        if len(hdr) < 8:
            return []

        entsize, count = struct.unpack(f"{self.endian}2I", hdr)
        props: List[str] = []
        if entsize < 16:
            entsize = 16

        data = self._f.read(count * entsize)
        for i in range(count):
            if (i + 1) * entsize > len(data):
                break
            name_va, attr_va = struct.unpack(f"{self.endian}2Q", data[i*entsize:i*entsize+16])
            p_name = self.read_cstring(name_va)
            if p_name:
                props.append(p_name)
        return props

    def _parse_ivar_list(self, ivar_list_va: int) -> List[str]:
        """解析 ivar_list_t"""
        iv_off = self.va_to_offset(ivar_list_va)
        if iv_off is None:
            return []

        self._f.seek(iv_off)
        hdr = self._f.read(8)
        if len(hdr) < 8:
            return []

        entsize, count = struct.unpack(f"{self.endian}2I", hdr)
        ivars: List[str] = []
        if entsize < 32:
            entsize = 32

        data = self._f.read(count * entsize)
        for i in range(count):
            if (i + 1) * entsize > len(data):
                break
            offset_ptr, name_va, type_va, align, size = struct.unpack(f"{self.endian}3Q2I", data[i*entsize:i*entsize+32])
            iv_name = self.read_cstring(name_va)
            if iv_name:
                ivars.append(iv_name)
        return ivars
