"""
PoC Name: N/A
CVE: N/A
Component: N/A
Category: N/A
Severity: N/A
CVSS: N/A
Description: N/A
Prerequisites: N/A
Usage: python3 iv_plugin_base.py <args>
"""
import abc
import json
import logging
import sys
import socket



class IVIVulnerabilityPlugin(metaclass=abc.ABCMeta):
    """
    智能网联汽车漏洞扫描插件基类 (Updated)
    强制执行标准化的漏洞验证生命周期：初始化 -> 环境检查 -> 执行利用 -> 结果反馈
    """
    # ====== PoC 元数据 (Metadata) ======
    meta_poc_name: str = "Unknown PoC"
    meta_cve_id: str = "Unknown CVE"
    meta_severity: str = "Unknown"  # Low, Medium, High, Critical
    meta_protocol: str = "Unknown"  # e.g., "tcp", "udp", "can", "someip"
    meta_target_os: list = []       # e.g., ["qnx", "android", "linux", "all"]
    meta_required_params: list = [] # e.g., ["target_ip", "port", "can_interface"]
    
    # 破坏性标志：若为 True，则 Agent 不会自动执行该 PoC，除非人工审核或在虚拟沙箱中
    is_disruptive: bool = False
    meta_destructive_level: str = "Safe" # Safe, Restart, DataLoss, Brick

    def __init__(self, target_config, logger=None):
        """
        :param target_config: 字典，包含 target_ip, target_port, interface 等配置
        :param logger: 日志记录器实例
        """
        self.target_ip = target_config.get('target_ip')
        self.target_port = target_config.get('target_port')
        self.interface = target_config.get('interface')
        self.timeout = target_config.get('timeout', 5)
        self.params = target_config # Store full config as params for flexibility
        
        # 配置默认日志
        if not logger:
            logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')
            self.logger = logging.getLogger(self.__class__.__name__)
        else:
            self.logger = logger
        
        self.logger.info(f"已初始化漏洞验证模块: {self.__class__.__name__}，目标: {self.target_ip}")

        self.results = {
            "vulnerable": False,
            "cve_id": "UNKNOWN",
            "description": "",
            "evidence": ""
        }

    @abc.abstractmethod
    def check_prerequisites(self):
        """
        前置条件检查
        验证运行环境（如网络接口、硬件适配器）及目标可达性。
        如果不满足条件，应抛出 RuntimeError 或返回 False。
        """
        pass

    @abc.abstractmethod
    def exploit(self):
        """
        核心利用逻辑
        包含构造恶意负载、发送数据包、处理响应等具体步骤。
        """
        pass

    def create_connection(self, protocol='tcp', timeout=None):
        """
        网络连接辅助函数
        """
        if timeout is None:
            timeout = self.timeout

        try:
            if protocol == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            elif protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                raise ValueError("不支持的协议类型")
            
            sock.settimeout(timeout)
            if self.target_ip and self.target_port:
                sock.connect((self.target_ip, int(self.target_port)))
            return sock
        except socket.error as e:
            self.logger.error(f"无法建立连接: {e}")
            return None

    def run_verify(self):
        """标准化的执行验证流程"""
        poc_display_name = self.params.get('poc_id', self.__class__.__name__)
        if 'poc_name' in self.params:
            poc_display_name += f" ({self.params['poc_name']})"

        print(f"\n[*] 正在启动检测任务: {poc_display_name}")
        print(f"[*] 描述: {self.results.get('description', '')}")
        
        try:
            self.logger.info("正在执行前置条件检查...")
            # Support both boolean return and exception raising
            prereq = self.check_prerequisites()
            if prereq is False:
                 raise RuntimeError("前置条件检查返回失败")
            
            self.logger.info("前置条件满足。开始执行漏洞验证...")
            exploit_result = self.exploit()
            self._merge_exploit_result(exploit_result)
            self.logger.info("漏洞验证流程结束。")

        except RuntimeError as re:
            print(f"[-][错误] 前置条件未满足: {re}。终止任务。")
            self.logger.warning(f"前置条件未满足: {re}")
            return # Exit without printing final verdict or print verdict as safe/error? Usually stop.
        except Exception as e:
            self.logger.error(f"脚本执行期间发生异常: {str(e)}")
            self.results["evidence"] = f"Exception: {str(e)}"
        
        self._print_final_verdict()

    def _merge_exploit_result(self, exploit_result):
        """
        兼容旧版 PoC 直接 return dict 的写法，把有效字段合并回 self.results。
        """
        if not isinstance(exploit_result, dict):
            return

        if "vulnerable" in exploit_result:
            self.results["vulnerable"] = bool(exploit_result.get("vulnerable"))
        if exploit_result.get("cve_id"):
            self.results["cve_id"] = exploit_result.get("cve_id")
        if exploit_result.get("description"):
            self.results["description"] = exploit_result.get("description")

        evidence = exploit_result.get("evidence")
        if not evidence:
            evidence = exploit_result.get("details")
        if evidence:
            self.results["evidence"] = str(evidence)

    def _print_final_verdict(self):
        poc_display_name = self.params.get('poc_id', self.__class__.__name__)
        print("\n" + "="*50)
        print(f"检测结果报告: {poc_display_name}")
        print("-" * 50)
        
        if self.results['vulnerable']:
            print(f"[!] 状态: 【漏洞存在】 (VULNERABLE)")
            print(f"[!] 证据: {self.results['evidence']}")
        else:
            print(f"[-] 状态: 【未检测到漏洞】 (NOT VULNERABLE)")
            if self.results['evidence']:
                print(f"[-] 信息: {self.results['evidence']}")
        
        print("="*50 + "\n")

    def get_report(self):
        """返回JSON格式的扫描报告"""
        return json.dumps(self.results, indent=4, ensure_ascii=False)
