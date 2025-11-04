# server/server.py
from scapy.all import sniff, IP, UDP
import datetime
import os
from collections import defaultdict
import time

# --- 설정값 ---
THRESHOLD = 3      # 이 패킷이 3회 이상 지속되면 블록대상
RATE_LIMIT_TIME = 10 # 10초 이내에 THRESHOLD 초과 시 차단
BLOCKED_IP = "server/data/blocklist.txt"
DETECTION_LOG = "server/data/logs/server.log"

# LAND 공격은 자신의 IP를 위조하므로, 탐지 대상 IP는 서버 자신의 IP로 설정.
detection_history = defaultdict(lambda: [])


def log_event(message, log_file):
    """이벤트 로그를 파일에 기록"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    print(log_entry.strip())
    with open(log_file, "a") as f:
        f.write(log_entry)

def is_blocked(ip):
    """블록리스트 확인"""
    if not os.path.exists(BLOCKED_IP):
        return False
    with open(BLOCKED_IP, "r") as f:
        return ip in [line.strip() for line in f.readlines()]

def add_to_blocklist(ip):
    """IP를 블록리스트에 등록"""
    if not is_blocked(ip):
        with open(BLOCKED_IP, "a") as f:
            f.write(f"{ip}\n")
        log_event(f"!!! BLOCKED !!! IP {ip} has been added to the blocklist (Rate Limit Exceeded).", DETECTION_LOG)

# --- 메인 탐지 로직 ---

def packet_handler(packet):
    """캡처된 패킷을 분석하고 LAND 공격을 탐지"""
    
    # 1. IP 및 UDP 계층 확인
    if not (packet.haslayer(IP) and packet.haslayer(UDP)):
        return

    ip_layer = packet[IP]
    udp_layer = packet[UDP]
    
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    src_port = udp_layer.sport
    dst_port = udp_layer.dport

    # 2. TTL 유효성 검사 (보조 로직)
    # TTL이 0이면 무한 루프이거나 잘못된 패킷일 가능성이 높으므로 경고
    if ip_layer.ttl == 0:
        log_event(f"TTL=0 Detected from {src_ip}", DETECTION_LOG)
        # TTL이 0인 패킷은 탐지 로직에서 제외하거나 별도로 처리 가능
        return

    # 3. LAND 공격 조건 검사 (src == dst, port 일치)
    if src_ip == dst_ip and src_port == dst_port:
        
        # 탐지 메시지
        land_msg = f"LAND-like Attack Detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (TTL={ip_layer.ttl})"
        log_event(land_msg, DETECTION_LOG)
        
        # 4. Rate-Limit 검사 및 차단 로직
        current_time = time.time()
        
        # 현재 IP의 기록 정리 (RATE_LIMIT_TIME보다 오래된 기록 제거)
        current_history = [
            t for t in detection_history[src_ip] 
            if current_time - t < RATE_LIMIT_TIME
        ]
        current_history.append(current_time)
        detection_history[src_ip] = current_history
        
        # Rate-Limit 초과 검사
        if len(detection_history[src_ip]) >= THRESHOLD:
            add_to_blocklist(src_ip)
            
    # 5. 블록된 IP의 패킷 처리 (소켓 통신 레벨에서 실제 차단 구현)
    # Raw Socket 스니퍼는 패킷을 무조건 수신하지만, 
    # 일반 서비스 포트(5000)가 블록리스트를 참조하여 차단하도록 설정 
    if is_blocked(src_ip):
         log_event(f"DROP Packet from Blocked IP: {src_ip}", DETECTION_LOG)
         # 여기서 패킷을 drop하는 것은 OS 레벨의 방화벽이 필요하며,
         # 이 프로토타입은 탐지 및 기록에 중점을 둡니다.

def run_sniffer(interface):
    """스니핑 시작"""
    print(f"[*] Starting LAND Detector on interface {interface}...")
    # 필터: UDP만 캡처
    sniff(iface=interface, filter="udp", prn=packet_handler, store=0)

if __name__ == "__main__":
    # 데이터 디렉토리 생성
    os.makedirs(os.path.dirname(DETECTION_LOG), exist_ok=True)
    
    # 도커 환경에서 일반적으로 사용되는 인터페이스 (환경에 따라 eth0 또는 다른 이름일 수 있음)
    # 실제 서버의 인터페이스 이름을 확인해야 합니다.
    # docker-compose로 실행 시, 컨테이너 내부의 주 인터페이스는 보통 eth0입니다.
    try:
        run_sniffer("eth0")
    except Exception as e:
        print(f"[ERROR] Sniffing failed. Check root privileges and interface name: {e}")