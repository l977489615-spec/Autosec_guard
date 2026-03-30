import socket
import sys
import time

def send_fuzz(target_ip, port, payload):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target_ip, port))
            print(f"Sending payload: {payload}")
            s.sendall(payload)
            response = s.recv(1024)
            if response:
                print(f"Received: {response}")
            else:
                print("No response from the server.")
    except Exception as e:
        print(f"An error occurred: {e}")
        # 如果遇到异常行为，认为可能存在漏洞
        print("Vulnerable: True")
        return True
    return False

def main():
    target_ip = "172.16.64.129"
    port = int(input("Enter the port number to fuzz: "))
    
    # 定义一些基本的模糊测试字符串
    payloads = [
        b"A" * 100,  # 长度为100的A字符
        b"\x00" * 100,  # NULL字节
        b"%" * 100,  # 百分号
        b".." * 100,  # 目录遍历
        b"HTTP/1.1 GET / HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n",  # 基本HTTP请求
        b"GET / HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n",  # 另一种格式的HTTP请求
        b"() { :;}; echo Vulnerable to Shellshock",  # Shellshock PoC
    ]
    
    for payload in payloads:
        print("\n" + "-"*50)
        print(f"Testing with payload: {payload}")
        if send_fuzz(target_ip, port, payload):
            break  # 如果发现漏洞，则停止进一步测试
        time.sleep(1)  # 等待一小段时间以避免过于频繁地发送请求

if __name__ == "__main__":
    main()