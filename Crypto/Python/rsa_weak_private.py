#!/usr/bin/env python3

import sys
import math
from sympy import isprime, nextprime 

def factorize(n):
    if n % 2 == 0: return 2, n//2
    i = 3
    while i*i <= n:
        if n % i == 0:
            return i, n//i
        i += 2
    return 1, n

def main():
    if len(sys.argv) != 2:
        print("Usage: rsa_weak_private.py \"{n: 123, e: 3, c: 456}\"")
        sys.exit(1)
    import ast
    data = ast.literal_eval(sys.argv[1])
    n = data['n']
    e = data['e']
    c = data['c']
    p, q = factorize(n)
    if p == 1:
        print("\033[91m[-] Failed to factor n\033[0m")
        return
    phi = (p-1)*(q-1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    print(f"\033[92m[+] p = {p}, q = {q}\033[0m")
    print(f"\033[92m[+] d = {d}\033[0m")
    print(f"\033[92m[+] Plaintext (int): {m}\033[0m")
    try:
        msg = m.to_bytes((m.bit_length()+7)//8, 'big').decode('utf-8', errors='ignore')
        print(f"\033[92m[+] Plaintext (str): {msg}\033[0m")
    except:
        pass

if __name__ == "__main__":
    main()