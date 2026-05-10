#!/usr/bin/env python3

import sys
from collections import Counter
import itertools

def ic(text):
    text = text.lower()
    text = [c for c in text if c.isalpha()]
    n = len(text)
    if n <= 1: return 0
    freq = Counter(text)
    return sum(f*(f-1) for f in freq.values()) / (n*(n-1))

def kasiski(cipher):
    cipher = cipher.lower()
    distances = []
    for l in range(3,6):
        seqs = {}
        for i in range(len(cipher)-l):
            sub = cipher[i:i+l]
            if sub in seqs:
                distances.append(i - seqs[sub])
            else:
                seqs[sub] = i
    if distances:
        from math import gcd
        g = distances[0]
        for d in distances[1:]:
            g = gcd(g, d)
        return max(1, g) if g > 0 else 1
    return 1

def shift_crack(cipher, keylen):
    cipher = cipher.lower()
    key = ''
    for i in range(keylen):
        block = [cipher[j] for j in range(i, len(cipher), keylen) if cipher[j].isalpha()]
        best_shift = 0
        best_score = 0
        for shift in range(26):
            dec = [chr(((ord(ch)-97 - shift) % 26) + 97) for ch in block]
            freq = Counter(dec)
            score = sum(freq.get(ch,0)*0.076 for ch in 'etaoin')
            if score > best_score:
                best_score = score
                best_shift = shift
        key += chr(best_shift + 97)
    return key

def main():
    if len(sys.argv) != 2:
        print("Usage: vigenere_breaker.py <ciphertext>")
        sys.exit(1)
    cipher = sys.argv[1]
    kl = kasiski(cipher)
    print(f"\033[93m[+] Estimated key length: {kl}\033[0m")
    key = shift_crack(cipher, kl)
    print(f"\033[92m[+] Key: {key}\033[0m")
    plain = ''
    for i, ch in enumerate(cipher):
        if ch.isalpha():
            shift = ord(key[i%len(key)]) - 97
            base = 65 if ch.isupper() else 97
            plain += chr(( (ord(ch)-base - shift) % 26 ) + base)
        else:
            plain += ch
    print(f"\033[92m[+] Plaintext: {plain}\033[0m")

if __name__ == "__main__":
    main()