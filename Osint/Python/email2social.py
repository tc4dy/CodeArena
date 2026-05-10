#!/usr/bin/env python3

import requests
import json
import sys
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor
import re

class Email2Social:
    def __init__(self, email):
        self.email = email
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    def gravatar(self):
        email_hash = hashlib.md5(self.email.lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/{email_hash}.json"
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code == 200:
                data = r.json()
                entry = data.get('entry', [{}])[0]
                self.results['gravatar'] = {
                    'displayName': entry.get('displayName'),
                    'profileUrl': entry.get('profileUrl'),
                    'aboutMe': entry.get('aboutMe')
                }
        except: pass

    def github(self):
        # Check if email associated with commits
        url = f"https://api.github.com/search/users?q={self.email}"
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code == 200:
                items = r.json().get('items', [])
                if items:
                    self.results['github'] = items[0]['html_url']
        except: pass

    def dehashed(self, api_key=None):
        if not api_key:
            return
        # Dehashed API (paid, but show structure)
        # For demo, skip real call
        pass

    def holehe(self):
        # like holehe library but manual
        sites = {
            'adobe': 'https://www.adobe.com',
            'facebook': 'https://www.facebook.com',
            'twitter': 'https://twitter.com',
            'instagram': 'https://www.instagram.com',
            'spotify': 'https://www.spotify.com',
            'firefox': 'https://accounts.firefox.com',
            'pinterest': 'https://www.pinterest.com',
            'tumblr': 'https://www.tumblr.com',
            'wordpress': 'https://wordpress.com',
            'linkedin': 'https://www.linkedin.com'
        }
        for site, url in sites.items():
            try:
                # Simulate registration check
                # Real implementation would use specific endpoints
                r = self.session.get(url + "/accounts/email/" + self.email, timeout=3)
                if r.status_code == 200:
                    self.results[site] = "possible"
            except:
                pass

    def epieos(self):
        # Google profile discovery
        try:
            r = self.session.get(f"https://epieos.com/api/v1/email/{self.email}")
            if r.status_code == 200:
                self.results['epieos'] = r.json()
        except: pass

    def run(self):
        print(f"[*] Scanning social media for {self.email}")
        self.gravatar()
        self.github()
        self.holehe()
        print(json.dumps(self.results, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: email2social.py email@example.com")
        sys.exit(1)
    e2s = Email2Social(sys.argv[1])
    e2s.run()