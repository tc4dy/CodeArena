#!/usr/bin/env python3

import sys
import hashlib
from capstone import *
from collections import defaultdict
import pefile
from elftools.elf.elffile import ELFFile

def extract_functions(binary_path):
    """Extract functions and their bytes (simplified via sections)"""
    functions = {}
    with open(binary_path, 'rb') as f:
        data = f.read()
    # Very naive: use entropy to split, but real implementation would use disassembly.
    # Here we use PE/ELF section alignment
    if data[:2] == b'MZ':
        pe = pefile.PE(data=data)
        text = None
        for sec in pe.sections:
            if b'.text' in sec.Name:
                text = sec.get_data()
                break
        if text:
            # split into 16-byte chunks and hash
            for i in range(0, len(text), 16):
                chunk = text[i:i+16]
                if chunk:
                    functions[hex(i)] = hashlib.sha256(chunk).hexdigest()
    else:
        # ELF
        import io
        elffile = ELFFile(io.BytesIO(data))
        text_sec = elffile.get_section_by_name('.text')
        if text_sec:
            text = text_sec.data()
            for i in range(0, len(text), 16):
                chunk = text[i:i+16]
                if chunk:
                    functions[hex(i)] = hashlib.sha256(chunk).hexdigest()
    return functions

def diff_binaries(bin1, bin2):
    funcs1 = extract_functions(bin1)
    funcs2 = extract_functions(bin2)
    common = set(funcs1.keys()) & set(funcs2.keys())
    only1 = set(funcs1.keys()) - set(funcs2.keys())
    only2 = set(funcs2.keys()) - set(funcs1.keys())
    print(f"Common chunks: {len(common)}")
    print(f"Only in {bin1}: {len(only1)}")
    print(f"Only in {bin2}: {len(only2)}")
    # detailed diff for changed chunks
    changed = []
    for k in common:
        if funcs1[k] != funcs2[k]:
            changed.append(k)
    print(f"Changed chunks: {len(changed)}")
    for chunk in changed[:10]:
        print(f"  {chunk} changed")
    return changed

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: 07_binary_diffing.py <binary1> <binary2>")
        sys.exit(1)
    diff_binaries(sys.argv[1], sys.argv[2])