import socket
import random
import string
import sys

def generate_random_string(length=10):
    """生成指定长度的随机字符串"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def fuzz(target_ip, port, timeout=5):
    """对指定端口进行模糊测试"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            print(f"Connected to {target_ip}:{port}")
            
            # 发送多条随机消息
            for i in range(100):  # 可以调整尝试次数
                payload = generate_random_string(random.randint(10, 100))  # 随机长度的消息
                print(f"Sending payload: {payload}")
                s.sendall(payload.encode())
                
                # 尝试接收响应
                response = s.recv(1024).decode()
                if "error" in response.lower() or "exception" in response.lower():
                    print("Vulnerable: True")
                    break
                else:
                    print(f"Received: {response}")

    except Exception as e:
        print(f"An error occurred: {e}")
        if "refused" not in str(e).lower():  # 如果不是连接被拒绝，则认为可能存在漏洞
            print("Vulnerable: True")

if __name__ == "__main__":
    target_ip = "172.16.64.129"
    port = 24  # 假设我们要测试的未知服务端口号
    fuzz(target_ip, port)