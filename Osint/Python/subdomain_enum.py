#!/usr/bin/env python3

import dns.resolver
import dns.zone
import requests
import sys
import threading
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import socket
import ssl
import subprocess

G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
B = "\033[94m"
N = "\033[0m"

class SubdomainPro:
    def __init__(self, domain, threads=50, output=None):
        self.domain = domain
        self.threads = threads
        self.output = output
        self.subs = set()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (OSINT Probe)'})

    def load_wordlist(self):
        # Built-in wordlist, can be extended
        words = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img", "download", "dns", "piwik", "stats", "dashboard", "portal", "manage", "start", "info", "apps", "video", "sip", "dns2", "api", "cdn", "mssql", "remote", "server", "ftp2", "stage", "vps", "monitor", "files", "backup", "ns4", "ns5", "ns6"]
        return words

    def resolve(self, sub):
        try:
            full = f"{sub}.{self.domain}"
            answers = dns.resolver.resolve(full, 'A')
            for rdata in answers:
                ip = str(rdata)
                with self.lock:
                    self.subs.add((full, ip))
                print(f"{G}[+] {full} -> {ip}{N}")
                return True
        except:
            return False

    def brute_force(self):
        wordlist = self.load_wordlist()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.resolve, w): w for w in wordlist}
            for future in as_completed(futures):
                pass

    def cert_transparency(self):
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name.endswith(f".{self.domain}"):
                        sub = name.rstrip('.')
                        self.resolve(sub)
        except Exception as e:
            print(f"{R}[-] crt.sh error: {e}{N}")

    def dnsdumpster(self):
        try:
            s = requests.Session()
            s.get("https://dnsdumpster.com")
            csrf = s.cookies.get('csrftoken')
            data = {'csrfmiddlewaretoken': csrf, 'targetip': self.domain}
            resp = s.post("https://dnsdumpster.com", data=data, headers={'Referer': 'https://dnsdumpster.com'})
            import re
            found = re.findall(r'<td class="col-md-4">([^<]+)\.' + re.escape(self.domain), resp.text)
            for f in found:
                self.resolve(f)
        except:
            pass

    def securitytrails(self, api_key=None):
        if not api_key:
            return
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': api_key}
            resp = self.session.get(url, headers=headers)
            data = resp.json()
            for sub in data.get('subdomains', []):
                self.resolve(sub)
        except:
            pass

    def run(self):
        print(f"{Y}[*] Starting OSINT subdomain enumeration on {self.domain}{N}")
        threads = [
            threading.Thread(target=self.brute_force),
            threading.Thread(target=self.cert_transparency),
            threading.Thread(target=self.dnsdumpster),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if self.output:
            with open(self.output, 'w') as f:
                for sub, ip in self.subs:
                    f.write(f"{sub},{ip}\n")
            print(f"{G}[+] Results saved to {self.output}{N}")
        print(f"{B}[*] Total unique subdomains: {len(self.subs)}{N}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [threads] [output]")
        sys.exit(1)
    dom = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    out = sys.argv[3] if len(sys.argv) > 3 else None
    sp = SubdomainPro(dom, thr, out)
    sp.run()