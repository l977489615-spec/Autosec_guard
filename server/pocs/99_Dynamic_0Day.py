import socket
import sys

def fuzz_target(target_ip, target_port, payload):
    try:
        # 创建一个TCP/IP套接字
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)  # 设置超时时间
            s.connect((target_ip, target_port))
            
            # 发送payload
            s.sendall(payload)
            
            # 接收响应
            response = s.recv(1024)
            print(f"Received: {response}")
            
    except socket.timeout:
        print("Connection timed out.")
    except ConnectionRefusedError:
        print("Connection was refused. Ensure the target service is running and accessible.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        print("Vulnerable: True")
        return False
    else:
        print("No exception caught, but check the application for unusual behavior or errors.")
        return True

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 fuzz_unknown_service.py <target_ip> <target_port> <payload>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    payload = bytes.fromhex(sys.argv[3])  # 假设payload是以十六进制形式给出

    print(f"[*] Fuzzing {target_ip}:{target_port} with payload: {sys.argv[3]}")
    
    result = fuzz_target(target_ip, target_port, payload)
    if not result:
        print("Potential vulnerability detected, further investigation recommended.")