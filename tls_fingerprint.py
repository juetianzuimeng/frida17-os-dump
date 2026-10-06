#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TLS 客户端握手指纹分析工具 (JA3 标准规范)
特性：
- 零第三方依赖，基于标准 Python 3 实现
- 支持 PCAP 离线文件分析
- 支持原始十六进制 (Hex) 报文快速解析
- 支持本地监听模式实时捕获客户端 TLS ClientHello 指纹
- 完全遵循 RFC 8701 规范对 GREASE 随机保留值进行过滤
"""

import sys
import os
import struct
import hashlib
import socket
import argparse

# RFC 8701: GREASE values for TLS
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


def is_grease(val: int) -> bool:
    return val in GREASE_VALUES


def parse_client_hello(data: bytes):
    """
    解析 TLS ClientHello 字节流，提取 JA3 参数
    支持接收包含 TLS Record 层的字节，也支持直接传入 Handshake 层的字节
    """
    offset = 0
    total_len = len(data)

    if total_len < 5:
        return None, "数据长度过短 (< 5 字节)"

    # 1. 检查是否带有 TLS Record 层 (0x16: Handshake)
    if data[0] == 0x16:
        offset = 5

    # 2. 检查 Handshake Type (0x01: Client Hello)
    if offset >= total_len or data[offset] != 0x01:
        return None, f"非 ClientHello 报文 (type: {data[offset] if offset < total_len else 'N/A'})"

    if offset + 4 > total_len:
        return None, "Handshake Header 截断"
    offset += 4

    # 3. Client Version (2 字节)
    if offset + 2 > total_len:
        return None, "Client Version 字段截断"
    client_version = struct.unpack("!H", data[offset:offset+2])[0]
    offset += 2

    # 4. Random (32 字节)
    if offset + 32 > total_len:
        return None, "Random 字段截断"
    offset += 32

    # 5. Session ID (1 字节长度 + 数据)
    if offset + 1 > total_len:
        return None, "Session ID 长度字段截断"
    session_id_len = data[offset]
    offset += 1 + session_id_len
    if offset > total_len:
        return None, "Session ID 数据截断"

    # 6. Cipher Suites (2 字节长度 + 列表)
    if offset + 2 > total_len:
        return None, "Cipher Suites 长度字段截断"
    cipher_len = struct.unpack("!H", data[offset:offset+2])[0]
    offset += 2
    if offset + cipher_len > total_len:
        return None, "Cipher Suites 数据截断"

    ciphers = []
    for i in range(0, cipher_len, 2):
        c = struct.unpack("!H", data[offset+i:offset+i+2])[0]
        if not is_grease(c):
            ciphers.append(c)
    offset += cipher_len

    # 7. Compression Methods (1 字节长度 + 列表)
    if offset + 1 > total_len:
        return None, "Compression Methods 长度字段截断"
    comp_len = data[offset]
    offset += 1 + comp_len
    if offset > total_len:
        return None, "Compression Methods 数据截断"

    # 8. Extensions (2 字节长度 + 扩展列表，可选)
    extensions = []
    elliptic_curves = []
    point_formats = []

    if offset + 2 <= total_len:
        ext_total_len = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        ext_end = min(offset + ext_total_len, total_len)

        while offset + 4 <= ext_end:
            ext_type = struct.unpack("!H", data[offset:offset+2])[0]
            ext_len = struct.unpack("!H", data[offset+2:offset+4])[0]
            offset += 4
            ext_data = data[offset:offset+ext_len]
            offset += ext_len

            if not is_grease(ext_type):
                extensions.append(ext_type)

                # Type 10: Supported Groups / Elliptic Curves
                if ext_type == 10 and len(ext_data) >= 2:
                    curves_len = struct.unpack("!H", ext_data[0:2])[0]
                    for j in range(2, min(2 + curves_len, len(ext_data)), 2):
                        curve = struct.unpack("!H", ext_data[j:j+2])[0]
                        if not is_grease(curve):
                            elliptic_curves.append(curve)

                # Type 11: EC Point Formats
                elif ext_type == 11 and len(ext_data) >= 1:
                    pf_len = ext_data[0]
                    for j in range(1, min(1 + pf_len, len(ext_data))):
                        point_formats.append(ext_data[j])

    # 9. 构造 JA3 规范字符串
    # 格式: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    ja3_string = (
        f"{client_version},"
        f"{'-'.join(str(c) for c in ciphers)},"
        f"{'-'.join(str(e) for e in extensions)},"
        f"{'-'.join(str(g) for g in elliptic_curves)},"
        f"{'-'.join(str(p) for p in point_formats)}"
    )
    ja3_hash = hashlib.md5(ja3_string.encode('utf-8')).hexdigest()

    return {
        "client_version": client_version,
        "ciphers": ciphers,
        "extensions": extensions,
        "elliptic_curves": elliptic_curves,
        "point_formats": point_formats,
        "ja3_string": ja3_string,
        "ja3_hash": ja3_hash
    }, None


def parse_pcap_file(pcap_path: str):
    """纯 Python 解析标准 PCAP 文件并提取 ClientHello"""
    if not os.path.exists(pcap_path):
        print(f"[-] 文件不存在: {pcap_path}")
        return

    results = []
    with open(pcap_path, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            print("[-] 无效 PCAP 文件: 头部数据过短")
            return

        magic = global_header[0:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2c\xd4":
            endian = ">"
        else:
            print(f"[-] 不支持的 PCAP 格式魔数: {magic.hex()}")
            return

        link_type = struct.unpack(endian + "I", global_header[20:24])[0]
        pkt_idx = 0

        while True:
            pkt_idx += 1
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", pkt_hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            offset = 0
            if link_type == 1:  # Ethernet
                if len(pkt_data) < 14:
                    continue
                eth_proto = struct.unpack("!H", pkt_data[12:14])[0]
                offset = 14
                if eth_proto != 0x0800:
                    continue
            elif link_type == 0:  # Loopback
                offset = 4
            elif link_type == 101:  # Raw IP
                offset = 0

            # IPv4
            if len(pkt_data) < offset + 20:
                continue
            ip_ver_ihl = pkt_data[offset]
            ihl = (ip_ver_ihl & 0x0F) * 4
            ip_proto = pkt_data[offset + 9]
            src_ip = socket.inet_ntoa(pkt_data[offset + 12:offset + 16])
            dst_ip = socket.inet_ntoa(pkt_data[offset + 16:offset + 20])
            offset += ihl

            if ip_proto != 6:  # TCP
                continue

            # TCP
            if len(pkt_data) < offset + 20:
                continue
            src_port = struct.unpack("!H", pkt_data[offset:offset + 2])[0]
            dst_port = struct.unpack("!H", pkt_data[offset + 2:offset + 4])[0]
            tcp_offset = ((pkt_data[offset + 12] >> 4) & 0x0F) * 4
            offset += tcp_offset

            payload = pkt_data[offset:]
            if len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x01:
                ja3_info, err = parse_client_hello(payload)
                if ja3_info:
                    results.append({
                        "packet_index": pkt_idx,
                        "session": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                        "ja3": ja3_info
                    })

    print(f"[*] PCAP 文件分析完成，捕获到 {len(results)} 个 ClientHello 握手包:")
    for r in results:
        print("=" * 60)
        print(f"包序号      : #{r['packet_index']}")
        print(f"会话连接    : {r['session']}")
        print(f"JA3 字符串  : {r['ja3']['ja3_string']}")
        print(f"JA3 Hash    : {r['ja3']['ja3_hash']}")


def listen_and_sniff(host: str, port: int):
    """启动本地 TCP 探测端口，实时接收客户端连接并输出 JA3 指纹"""
    print(f"[*] 启动本地监听: {host}:{port} (等待客户端发起 TLS 握手...)")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)

    try:
        while True:
            conn, addr = server.accept()
            try:
                data = conn.recv(4096)
                if data:
                    ja3_info, err = parse_client_hello(data)
                    if ja3_info:
                        print("=" * 60)
                        print(f"客户端来源  : {addr[0]}:{addr[1]}")
                        print(f"TLS 版本    : {ja3_info['client_version']}")
                        print(f"套件数量    : {len(ja3_info['ciphers'])} 个")
                        print(f"扩展数量    : {len(ja3_info['extensions'])} 个")
                        print(f"JA3 字符串  : {ja3_info['ja3_string']}")
                        print(f"JA3 Hash    : {ja3_info['ja3_hash']}")
                    else:
                        print(f"[-] 收到来自 {addr} 的非 ClientHello 数据: {err}")
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("\n[*] 退出监听。")
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(description="通用 TLS ClientHello 指纹 (JA3) 分析工具")
    parser.add_argument("--pcap", type=str, help="分析指定的 PCAP 抓包文件")
    parser.add_argument("--hex", type=str, help="直接解析十六进制字符串形式的 ClientHello 报文")
    parser.add_argument("--listen", type=int, help="启动本地 TCP 端口监听模式 (如 8443)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="监听地址 (默认 0.0.0.0)")

    args = parser.parse_args()

    if args.pcap:
        parse_pcap_file(args.pcap)
    elif args.hex:
        raw_bytes = bytes.fromhex(args.hex.replace(" ", "").replace("\n", ""))
        ja3_info, err = parse_client_hello(raw_bytes)
        if err:
            print(f"[-] 解析失败: {err}")
        else:
            print("=" * 60)
            print(f"JA3 字符串 : {ja3_info['ja3_string']}")
            print(f"JA3 Hash   : {ja3_info['ja3_hash']}")
    elif args.listen:
        listen_and_sniff(args.host, args.listen)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
