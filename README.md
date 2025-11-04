# Find-Land-Like-Project
본 프로젝트는 Raw Socket을 사용하여 LAND-like 이벤트(송신자와 수신자의 IP/포트가 동일한 패킷)를 Docker container 환경에서 탐지하고, 반복 발생 시 블록리스트에 등록하여 차단하는 프로토타입을 시뮬레이션 합니다.

## 시뮬레이션 실행 방법  
- 빌드 및 실행

```
docker compose up --build -d
```  
   
  
## 패킷 캡쳐 (tcpdump사용)
```
docker exec -it find-land-like-project-server-1 /bin/bash
# 컨테이너 내부에서:
tcpdump -i eth0 -n udp port 5000
```  
- 클라이언트에서 공격 실행  
```
docker exec find-land-like-project-client-1 python client.py
```  
- tcpdump 결과 확인  



