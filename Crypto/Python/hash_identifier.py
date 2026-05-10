#!/usr/bin/env python3

import sys
import re
from collections import defaultdict

def identify(hash_str):
    patterns = {
        "MD5": r'^[a-fA-F0-9]{32}$',
        "SHA1": r'^[a-fA-F0-9]{40}$',
        "SHA256": r'^[a-fA-F0-9]{64}$',
        "SHA512": r'^[a-fA-F0-9]{128}$',
        "NTLM": r'^[a-fA-F0-9]{32}$',  # same as MD5 but context
        "MySQL": r'^[a-fA-F0-9]{41}$', # star prefix
        "bcrypt": r'^\$2[aby]\$\d+\$.+$'
    }
    results = defaultdict(float)
    if hash_str.startswith('$2'):
        results['bcrypt'] = 1.0
    elif hash_str.startswith('*'):
        results['MySQL'] = 0.9
    else:
        for name, pattern in patterns.items():
            if re.match(pattern, hash_str):
                score = 1.0 if name != 'NTLM' else 0.7
                results[name] = score
    if len(results) == 0:
        print("\033[91m[-] Unknown hash\033[0m")
    else:
        for name, score in sorted(results.items(), key=lambda x: x[1], reverse=True):
            print(f"\033[92m[+] {name} (confidence: {score})\033[0m")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: hash_identifier.py <hash>")
        sys.exit(1)
    identify(sys.argv[1])