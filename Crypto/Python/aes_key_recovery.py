#!/usr/bin/env python3

import sys
from Crypto.Cipher import AES  

def ecb_recover(known_plain, ciphertext):
    # AES-128 varsayıyoruz
    possible_keys = []
    for key_candidate in range(256):
        key = bytes([key_candidate]) * 16
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(ciphertext)
        if known_plain in dec:
            possible_keys.append(key)
    return possible_keys

def main():
    if len(sys.argv) != 3:
        print("Usage: aes_key_recovery.py <known_plaintext> <ciphertext_hex>")
        sys.exit(1)
    known = sys.argv[1].encode()
    cipher = bytes.fromhex(sys.argv[2])
    keys = ecb_recover(known, cipher)
    if keys:
        print(f"\033[92m[+] Found {len(keys)} possible keys:\033[0m")
        for k in keys:
            print(k.hex())
    else:
        print("\033[91m[-] No key found\033[0m")

if __name__ == "__main__":
    main()