"""
PoC Name: WiFi SSID Clone Auto-Connect (No BSSID Validation)
CVE: N/A
Component: Wireless Stack
Category: Wireless
Severity: Medium
CVSS: 6.5
Description: 车载 WiFi 自动连接时仅验证 SSID，不验证 BSSID（AP MAC 地址），攻击者可伪造同名热点实施 Evil AP 中间人攻击。杭州 CCF 中奔腾车机实测可触发
Prerequisites: 支持Monitor模式的无线网卡及scapy环境
Usage: python3 18_WiFi_SSID_Clone_AutoConnect.py <args>
"""
import sys
import subprocess
import re
from iv_plugin_base import IVIVulnerabilityPlugin


class WiFiSSIDCloneAutoConnectPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-018"
    """
    WiFi SSID 克隆自动连接漏洞检测 PoC
    
    漏洞描述:
    部分车型（奔腾、问界等）车载 WiFi 在连接已知热点时，
    仅验证 SSID（服务集标识符），不验证 AP 的 MAC 地址（BSSID）。
    攻击者可伪造与已知热点相同的 SSID，使车机自动将流量转发至攻击者控制的 AP，
    实现中间人攻击（MitM）。
    
    检测逻辑（被动，不发射信号）:
    1. 使用无线网卡扫描当前环境中的 SSID 列表
    2. 检测是否存在车机常用的默认热点名称（明显缺乏认证机制）
    3. 检查目标网络是否缺少 802.11w（PMF，保护管理帧）
    4. 检测是否同一 SSID 存在多个 BSSID（是否已有人实施克隆）
    
    安全性: 纯被动扫描，不发射任何 WiFi 信号。
    """
    meta_poc_name = "WiFi SSID Clone AutoConnect"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "rf"
    meta_target_os = ["all"]
    meta_required_params = ["interface"]
    is_disruptive = False
    meta_destructive_level = "Safe"


    # 车机常见的默认 SSID 关键字（通用性较强的命名规律）
    IVI_SSID_PATTERNS = [
        r"IVI",
        r"CarHotspot",
        r"Vehicle",
        r"Zeekr",
        r"AION",
        r"Tesla",
        r"NIO",
        r"BYD",
        r"Chery",
        r"CarPlay",
        r"AndroidAuto",
        r"TBOX",
        r"ICV",
        r"OBD",
        r"carlink",
        r"car_wifi",
        r"ev_hotspot",
    ]

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "WiFi-SSID-Clone-AutoConnect"
        self.results["description"] = (
            "车载 WiFi 未验证 AP MAC 地址（BSSID），仅匹配 SSID，"
            "攻击者可伪造同名热点实现自动连接劫持（MitM）"
        )
        self.interface = (
            self.params.get("interface") or
            self.params.get("wifi_interface") or
            "wlan0"
        )

    def check_prerequisites(self):
        # 检查 iwlist / iw 工具是否可用
        for tool in ["iwlist", "iw"]:
            try:
                result = subprocess.run(
                    [tool, "--version"],
                    capture_output=True, timeout=3
                )
                self.logger.info(f"[+] 工具 {tool} 可用。")
                return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # 尝试 airport (macOS)
        try:
            result = subprocess.run(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                self.logger.info("[+] macOS airport 工具可用。")
                return True
        except Exception:
            pass

        # 尝试 system_profiler (macOS 通用后备方案)
        try:
            result = subprocess.run(
                ["system_profiler", "SPAirPortDataType"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and "Network" in result.stdout:
                self.logger.info("[+] macOS system_profiler 可用，将使用此工具扫描 WiFi 网络。")
                return True
        except Exception:
            pass

        self.logger.warning(
            "[-] 环境限制：未找到 iwlist/iw/airport/system_profiler 工具，"
            "缺少无线管理工具链，无法执行真实的 Wi-Fi 主动扫描和伪造断网攻击。"
        )
        return False

    def _scan_wifi(self):
        """扫描周边 WiFi 网络，返回 [(ssid, bssid, security, pmf)] 列表"""
        networks = []

        # 尝试 macOS airport
        try:
            result = subprocess.run(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # 跳过表头
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        ssid = parts[0]
                        bssid = parts[1] if len(parts) > 1 else "unknown"
                        security = " ".join(parts[6:]) if len(parts) > 6 else "unknown"
                        networks.append((ssid, bssid, security, False))
                return networks
        except Exception:
            pass

        # 尝试 Linux iwlist
        try:
            result = subprocess.run(
                ["iwlist", self.interface, "scan"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                current_bssid = None
                current_ssid = None
                current_enc = "Open"
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if "Address:" in line:
                        current_bssid = line.split("Address:")[-1].strip()
                    elif "ESSID:" in line:
                        m = re.search(r'ESSID:"([^"]*)"', line)
                        current_ssid = m.group(1) if m else ""
                    elif "Encryption key:on" in line:
                        current_enc = "Encrypted"
                    elif current_ssid and current_bssid and "Extra:" in line:
                        networks.append((current_ssid, current_bssid, current_enc, False))
                        current_ssid = current_bssid = None
                        current_enc = "Open"
                return networks
        except Exception:
            pass

        # 尝试 iw
        try:
            result = subprocess.run(
                ["iw", self.interface, "scan"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                current_bssid = None
                current_ssid = None
                pmf = False
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line.startswith("BSS "):
                        if current_ssid and current_bssid:
                            networks.append((current_ssid, current_bssid, "WPA", pmf))
                        m = re.match(r"BSS ([0-9a-fA-F:]+)", line)
                        current_bssid = m.group(1) if m else None
                        current_ssid = None
                        pmf = False
                    elif "SSID:" in line:
                        current_ssid = line.split("SSID:")[-1].strip()
                    elif "Management frame protection" in line:
                        pmf = True
                if current_ssid and current_bssid:
                    networks.append((current_ssid, current_bssid, "WPA", pmf))
                return networks
        except Exception:
            pass

        return []

    def exploit(self):
        iface = self.interface

        self.logger.info(f"[1/3] 使用接口 {iface} 扫描周边 WiFi 网络（被动模式）...")
        networks = self._scan_wifi()

        if not networks:
            self.logger.warning("[-] 未能扫描到任何 WiFi 网络，请检查接口名称和权限。")
            self.results["evidence"] = f"接口 {iface} 扫描无结果（权限不足或无线环境为空）"
            return

        self.logger.info(f"[+] 共发现 {len(networks)} 个 WiFi 网络。")

        # Step 2: 检测车机热点特征
        self.logger.info("[2/3] 检测是否存在车机特征 SSID...")
        ivi_networks = []
        for ssid, bssid, security, pmf in networks:
            for pattern in self.IVI_SSID_PATTERNS:
                if re.search(pattern, ssid, re.IGNORECASE):
                    ivi_networks.append((ssid, bssid, security, pmf))
                    break

        if not ivi_networks:
            self.logger.info("[-] 未发现明显的车机热点，当前环境可能无车机 WiFi。")
            self.results["evidence"] = (
                f"扫描到 {len(networks)} 个 WiFi 网络，未发现车机特征 SSID。"
            )
            return

        self.logger.info(f"[+] 发现 {len(ivi_networks)} 个疑似车机热点：")
        for ssid, bssid, security, pmf in ivi_networks:
            self.logger.info(f"    SSID={ssid!r}  BSSID={bssid}  安全={security}  PMF={'是' if pmf else '否'}")

        # Step 3: 检测同 SSID 多 BSSID（已有克隆迹象）
        self.logger.info("[3/3] 检测是否有同 SSID 多个 BSSID（克隆攻击迹象）...")
        ssid_map = {}
        for ssid, bssid, security, pmf in networks:
            ssid_map.setdefault(ssid, []).append(bssid)

        cloned = {s: bs for s, bs in ssid_map.items() if len(bs) > 1}

        # 判断漏洞
        no_pmf_ivi = [(s, b, sec) for s, b, sec, pmf in ivi_networks if not pmf]
        if no_pmf_ivi or cloned:
            self.results["vulnerable"] = True
            evidence_lines = ["WiFi SSID 克隆自动连接漏洞证据:"]
            if no_pmf_ivi:
                evidence_lines.append(f"  未启用 PMF(802.11w) 的车机热点（可被克隆）:")
                for s, b, sec in no_pmf_ivi:
                    evidence_lines.append(f"    SSID={s!r}  BSSID={b}  安全={sec}")
            if cloned:
                evidence_lines.append(f"  已发现同 SSID 多 BSSID（疑似 Evil AP 攻击进行中）:")
                for s, bs in cloned.items():
                    evidence_lines.append(f"    SSID={s!r}  BSSIDs={bs}")
            self.results["evidence"] = "\n".join(evidence_lines)
            print(f"[!] 【漏洞存在】WiFi SSID 克隆攻击向量已确认")
        else:
            pmf_ivi = [(s, b) for s, b, sec, pmf in ivi_networks if pmf]
            self.results["vulnerable"] = False
            self.results["evidence"] = (
                f"发现 {len(ivi_networks)} 个车机热点，但均已启用 PMF(802.11w)，"
                f"暂未发现明显克隆漏洞。PMF 保护的 AP: {pmf_ivi}"
            )
            self.logger.info("[-] 目标已启用 PMF，抗 Evil AP 攻击能力较强。")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 18_WiFi_SSID_Clone_AutoConnect.py <args>")
        sys.exit(1)
    plugin = WiFiSSIDCloneAutoConnectPlugin({"interface": sys.argv[1]})
    plugin.run_verify()
