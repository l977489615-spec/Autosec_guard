import socket
import struct
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin


class SOMEIPServiceDiscoveryPlugin(IVIVulnerabilityPlugin):
    """
    SOME/IP 服务发现（SD）信息泄露 PoC
    
    漏洞描述:
    SOME/IP（Scalable service-Oriented MiddlEware over IP）是众多主流车型
    （奔驰、宝马、大众 MEB 平台、极氪等）车载以太网的核心中间件协议。
    其 Service Discovery 机制通过 UDP 组播/单播广播服务列表，
    且默认无认证机制。攻击者接入车载以太网后，可枚举全部 ECU 服务及控制端口，
    进而针对性地发起注入或中间人攻击。
    
    检测逻辑:
    1. 向 SOME/IP SD 广播地址（224.0.0.1:30490）发送 FindService 消息
    2. 同时监听目标 IP 的 SD 单播响应（30490 端口）
    3. 解析 OfferService 响应，提取服务 ID、实例 ID、协议、端口等信息
    
    安全性: 仅发 1 个探测包，不修改任何 ECU 状态。
    
    参考标准: AUTOSAR R20-11 SOME/IP-SD 规范
    """

    # SOME/IP 魔数及常量
    SOMEIP_MAGIC = 0xFFFF
    SD_SERVICE_ID = 0xFFFF
    SD_METHOD_ID = 0x8100
    CLIENT_ID = 0xDEAD
    SESSION_ID = 0x0001
    PROTO_VER = 0x01
    IFACE_VER = 0x01
    MSG_TYPE_REQUEST = 0x00
    RETURN_CODE_OK = 0x00
    SD_PORT = 30490
    SD_MCAST = "224.0.0.1"
    ENTRY_TYPE_FINDSERVICE = 0x00
    ENTRY_TYPE_OFFERSERVICE = 0x01

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "SOMEIP-SD-Info-Leak"
        self.results["description"] = (
            "SOME/IP Service Discovery 未认证服务枚举 - "
            "攻击者可枚举车内全部 ECU SOME/IP 服务列表（ID/实例/协议/端口）"
        )

    def check_prerequisites(self):
        if not self.target_ip:
            self.logger.error("需要指定目标 IP 地址（参数: ip 或 target_ip）")
            return False
        return True

    def _build_someip_sd_find(self):
        """
        构造 SOME/IP SD FindService Entry Message
        
        格式:
        SOME/IP Header (16 bytes) + SD Header (4 bytes) + Entries Array + Options Array
        """
        # FindService Entry (16 bytes)
        entry = struct.pack(
            ">BBHHHBBHH",
            self.ENTRY_TYPE_FINDSERVICE,  # Type
            0x00,                          # Index 1st Options
            0x0000,                        # Index 2nd Options / Num Options 1 & 2
            0xFFFF,                        # Service ID (wildcard - all services)
            0xFFFF,                        # Instance ID (wildcard)
            0x01,                          # Major Version
            0x00,                          # TTL high byte
            0x0000,                        # TTL mid bytes
            0xFFFF,                        # TTL low word / Minor Version (0xFFFFFFFF)
        )
        # Correct TTL to 0xFFFFFFFF (wildcard) - use full 4 bytes for TTL
        entry = struct.pack(
            ">BBHHHBI",
            self.ENTRY_TYPE_FINDSERVICE,   # Type (1)
            0x00,                          # Index 1st Options (1)
            0x0000,                        # Index 2nd / Num Options (2)
            0xFFFF,                        # Service ID (2)
            0xFFFF,                        # Instance ID (2)
            0x01,                          # Major Version (1)
            0xFFFFFFFF,                    # TTL[3] + Minor Version[4] combined
        )

        entries_array_len = len(entry)
        options_array_len = 0

        # SD 载荷 = 标志(1) + 保留(3) + entries_len(4) + entries + options_len(4)
        sd_payload = struct.pack(">B3sI", 0xC0, b"\x00\x00\x00", entries_array_len)
        sd_payload += entry
        sd_payload += struct.pack(">I", options_array_len)

        payload_len = 8 + len(sd_payload)  # SOME/IP header 后的长度

        # SOME/IP Header (16 bytes):
        # Service ID(2) + Method ID(2) + Length(4) + Client ID(2) + Session ID(2)
        # + Proto Ver(1) + Iface Ver(1) + Msg Type(1) + Return Code(1)
        header = struct.pack(
            ">HHIHHBBBB",
            self.SD_SERVICE_ID,    # 0xFFFF
            self.SD_METHOD_ID,     # 0x8100
            payload_len,           # Length (everything after length field)
            self.CLIENT_ID,        # Client ID
            self.SESSION_ID,       # Session ID
            self.PROTO_VER,        # Protocol Version
            self.IFACE_VER,        # Interface Version
            self.MSG_TYPE_REQUEST, # Message Type (Request)
            self.RETURN_CODE_OK,   # Return Code
        )

        return header + sd_payload

    def _parse_sd_response(self, data):
        """
        解析 SOME/IP SD OfferService 响应
        返回发现的服务列表 [(service_id, instance_id, major_ver, port, proto)]
        """
        services = []
        if len(data) < 16:
            return services

        try:
            # 解析 SOME/IP 头
            srv_id, method_id, length, client_id, sess_id, \
            proto_ver, iface_ver, msg_type, ret_code = struct.unpack_from(">HHIHHBBBB", data, 0)

            # 检查是否是 SD 消息（Service ID=0xFFFF, Method ID=0x8100）
            if srv_id != 0xFFFF or method_id != 0x8100:
                return services

            offset = 16  # 跳过 SOME/IP 头
            if offset + 4 > len(data):
                return services

            # 解析 SD 标志和保留字段
            offset += 4  # flags(1) + reserved(3)

            # 解析 Entries Array
            if offset + 4 > len(data):
                return services
            entries_len = struct.unpack_from(">I", data, offset)[0]
            offset += 4

            entries_end = offset + entries_len
            while offset + 16 <= min(entries_end, len(data)):
                entry_type = data[offset]
                if entry_type == self.ENTRY_TYPE_OFFERSERVICE:
                    # OfferService Entry
                    _, idx1, idx2_count, service_id, instance_id, \
                    major_ver, ttl_high = struct.unpack_from(">BBHHHBB", data, offset)
                    ttl_low = struct.unpack_from(">H", data, offset + 10)[0]
                    minor_ver = struct.unpack_from(">I", data, offset + 12)[0]
                    services.append({
                        "service_id": f"0x{service_id:04X}",
                        "instance_id": f"0x{instance_id:04X}",
                        "major_version": major_ver,
                        "minor_version": minor_ver,
                    })
                offset += 16

        except struct.error as e:
            self.logger.debug(f"SOME/IP 响应解析异常: {e}")

        return services

    def exploit(self):
        host = self.target_ip

        self.logger.info(f"[1/3] 构造 SOME/IP SD FindService 消息（wildcard：发现所有服务）...")
        find_msg = self._build_someip_sd_find()
        self.logger.info(f"[*] 消息长度: {len(find_msg)} 字节")

        # 创建接收 socket
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.settimeout(self.timeout)
        try:
            recv_sock.bind(("0.0.0.0", self.SD_PORT))
        except OSError:
            # 端口被占用时，绑定随机端口
            recv_sock.bind(("0.0.0.0", 0))
            self.logger.info("[*] SD 端口已被占用，使用随机端口接收响应。")

        # 发送探测包（同时发送至组播和目标单播）
        self.logger.info(f"[2/3] 发送 FindService 探测至 {host}:{self.SD_PORT} 和组播...")
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # 单播发送至目标
            send_sock.sendto(find_msg, (host, self.SD_PORT))
            # 组播发送（仅在同一局域网生效）
            send_sock.sendto(find_msg, (self.SD_MCAST, self.SD_PORT))
        except Exception as e:
            self.logger.debug(f"发送异常: {e}")
        finally:
            send_sock.close()

        # 监听响应
        self.logger.info("[3/3] 监听 SOME/IP SD OfferService 响应（最多 5 秒）...")
        discovered_services = []
        responding_ips = set()
        start = time.time()

        while time.time() - start < self.timeout:
            try:
                data, addr = recv_sock.recvfrom(65507)
                src_ip = addr[0]
                if src_ip == host or src_ip.startswith(host.rsplit(".", 1)[0]):
                    self.logger.info(f"[+] 收到来自 {src_ip} 的响应, 长度={len(data)}")
                    services = self._parse_sd_response(data)
                    if services:
                        responding_ips.add(src_ip)
                        for svc in services:
                            svc["source_ip"] = src_ip
                            discovered_services.append(svc)
                            self.logger.info(
                                f"    [服务] ServiceID={svc['service_id']}  "
                                f"InstanceID={svc['instance_id']}  "
                                f"Version={svc['major_version']}.{svc['minor_version']}"
                            )
                    elif len(data) >= 16:
                        # 收到 SOME/IP 消息但解析不到 OfferService，仍是重要证据
                        responding_ips.add(src_ip)
                        self.logger.info(f"    [*] 目标响应了 SOME/IP 消息（未解析到服务条目）")
            except socket.timeout:
                break
            except Exception as e:
                self.logger.debug(f"接收异常: {e}")
                break

        recv_sock.close()

        # 判断结果
        if discovered_services:
            self.results["vulnerable"] = True
            svc_summary = "\n".join(
                f"  ServiceID={s['service_id']}, InstanceID={s['instance_id']}, "
                f"v{s['major_version']}.{s['minor_version']} (from {s.get('source_ip', 'unknown')})"
                for s in discovered_services
            )
            self.results["evidence"] = (
                f"SOME/IP SD 服务枚举成功，发现 {len(discovered_services)} 个车内服务：\n"
                f"{svc_summary}\n"
                f"  响应来源 IP: {responding_ips}"
            )
            print(f"[!] 【漏洞存在】SOME/IP SD 未认证服务枚举 - 发现 {len(discovered_services)} 个 ECU 服务")
        elif responding_ips:
            self.results["vulnerable"] = True
            self.results["evidence"] = (
                f"目标 {host} 响应了 SOME/IP SD 探测包（端口 {self.SD_PORT} 开放），"
                f"但未能解析 OfferService 条目（可能需要更完整的 SOME/IP 支持库）。"
                f"来源 IP: {responding_ips}"
            )
            print(f"[!] 【疑似漏洞】SOME/IP 服务开放（{responding_ips}），建议使用专用工具深入分析")
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = (
                f"未收到 SOME/IP SD 响应。目标 {host} 可能未运行 SOME/IP，"
                f"或 SD 组播仅在同一 VLAN 内有效。"
            )
            self.logger.info("[-] 未收到 SOME/IP 响应，目标可能未使用 SOME/IP 协议。")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 66_SOMEIP_Service_Discovery.py <target_ip>")
        print("示例: python3 66_SOMEIP_Service_Discovery.py 192.168.100.1")
        sys.exit(1)
    config = {"target_ip": sys.argv[1]}
    plugin = SOMEIPServiceDiscoveryPlugin(config)
    plugin.run_verify()
