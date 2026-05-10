#!/usr/bin/env python3

import sys
import os
import struct
import hashlib
import json
import argparse
from collections import defaultdict

try:
    import pefile
    import elftools
    from elftools.elf.elffile import ELFFile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    from capstone.x86 import X86_INS_RET, X86_INS_JMP, X86_INS_CALL
except ImportError as e:
    print(f"[!] Missing required library: {e}. Install: pip install pefile pyelftools capstone")
    sys.exit(1)

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    counts = defaultdict(int)
    for b in data:
        counts[b] += 1
    ent = 0.0
    for cnt in counts.values():
        p = cnt / len(data)
        ent -= p * math.log2(p)
    return ent

def find_rop_gadgets(code_bytes, arch='x86', bits=32):
    """Extract RET-ending instructions as potential ROP gadgets."""
    if arch == 'x86':
        mode = CS_MODE_32 if bits == 32 else CS_MODE_64
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True
        gadgets = []
        offset = 0
        while offset < len(code_bytes):
            insts = list(md.disasm(code_bytes[offset:], offset))
            if not insts:
                break
            # check if last instruction is RET
            if insts[-1].id == X86_INS_RET:
                gadget_bytes = code_bytes[offset:offset+insts[-1].size]
                gadgets.append((hex(offset), '; '.join([f"{i.mnemonic} {i.op_str}" for i in insts]), gadget_bytes))
            offset += insts[0].size
        return gadgets
    return []

def detect_anti_debug(pe=None, elf=None):
    """Heuristics for anti-debug tricks."""
    indicators = []
    if pe:
        for section in pe.sections:
            name = section.Name.decode().rstrip('\x00')
            if '.idata' in name:
                # check for IsDebuggerPresent, NtGlobalFlag
                data = section.get_data()
                if b'IsDebuggerPresent' in data:
                    indicators.append("Import: IsDebuggerPresent")
                if b'CheckRemoteDebuggerPresent' in data:
                    indicators.append("Import: CheckRemoteDebuggerPresent")
                if b'NtQueryInformationProcess' in data:
                    indicators.append("Import: NtQueryInformationProcess (possible anti-debug)")
        # TLS callbacks (indicator)
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
            indicators.append("TLS Callback present (anti-debug often uses it)")
    return indicators

def analyze_pe(filepath):
    """Full PE analysis."""
    pe = pefile.PE(filepath)
    report = {}
    report['type'] = 'PE'
    report['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    report['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
    report['sections'] = []
    high_entropy = False
    for sec in pe.sections:
        sec_data = sec.get_data()
        ent = entropy(sec_data)
        report['sections'].append({
            'name': sec.Name.decode().rstrip('\x00'),
            'virtual_size': hex(sec.Misc_VirtualSize),
            'raw_size': sec.SizeOfRawData,
            'entropy': round(ent, 2),
            'characteristics': hex(sec.Characteristics)
        })
        if ent > 7.0:
            high_entropy = True
    report['packer_detected'] = high_entropy
    # imports
    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            for imp in entry.imports:
                if imp.name:
                    imports.append(f"{dll}:{imp.name.decode()}")
    report['imports'] = imports[:50]  # limit
    # exports
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode())
    report['exports'] = exports
    # strings (simple ascii)
    strings = []
    for sec in pe.sections:
        data = sec.get_data()
        ascii_str = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
        # naive: split on null
        for w in ascii_str.split('\x00'):
            if len(w) > 4 and w.isprintable():
                strings.append(w)
    report['strings'] = list(set(strings))[:100]
    # anti-debug
    report['anti_debug_indicators'] = detect_anti_debug(pe=pe)
    # ROP gadgets (from .text section)
    text_sec = None
    for sec in pe.sections:
        if b'.text' in sec.Name:
            text_sec = sec
            break
    if text_sec:
        code = text_sec.get_data()
        rops = find_rop_gadgets(code, arch='x86', bits=pe.OPTIONAL_HEADER.Magic == 0x10b and 32 or 64)
        report['rop_gadgets'] = [{'offset': off, 'asm': asm} for off, asm, _ in rops[:20]]
    return report

def analyze_elf(filepath):
    """ELF analysis using pyelftools."""
    with open(filepath, 'rb') as f:
        elf = ELFFile(f)
        report = {}
        report['type'] = 'ELF'
        report['entry_point'] = hex(elf.header.e_entry)
        report['sections'] = []
        high_entropy = False
        for section in elf.iter_sections():
            data = section.data()
            ent = entropy(data) if data else 0
            report['sections'].append({
                'name': section.name,
                'size': section['sh_size'],
                'entropy': round(ent,2)
            })
            if ent > 7.0:
                high_entropy = True
        report['packer_detected'] = high_entropy
        # dynamic symbols (simplified)
        symtab = elf.get_section_by_name('.dynsym')
        imports = []
        if symtab:
            for sym in symtab.iter_symbols():
                if sym.name:
                    imports.append(sym.name)
        report['imports'] = imports[:50]
        # strings from .rodata / .strtab
        strings = []
        strtab = elf.get_section_by_name('.strtab')
        if strtab:
            data = strtab.data()
            for s in data.split(b'\x00'):
                try:
                    dec = s.decode()
                    if len(dec) > 3 and dec.isprintable():
                        strings.append(dec)
                except:
                    pass
        report['strings'] = list(set(strings))[:100]
        # anti-debug: check for ptrace, etc. in imports
        anti = []
        if 'ptrace' in imports:
            anti.append('ptrace call detected')
        report['anti_debug_indicators'] = anti
        # ROP gadgets from .text
        text_sec = elf.get_section_by_name('.text')
        if text_sec:
            code = text_sec.data()
            rops = find_rop_gadgets(code, arch='x86', bits=64 if elf.header.e_machine == 'EM_X86_64' else 32)
            report['rop_gadgets'] = [{'offset': off, 'asm': asm} for off, asm, _ in rops[:20]]
        return report

def main():
    parser = argparse.ArgumentParser(description='Static Binary Analyzer')
    parser.add_argument('binary', help='Path to PE/ELF binary')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()
    if not os.path.isfile(args.binary):
        print(f"{Colors.FAIL}File not found{Colors.ENDC}")
        sys.exit(1)
    # Detect type
    with open(args.binary, 'rb') as f:
        magic = f.read(2)
    if magic == b'MZ':
        report = analyze_pe(args.binary)
    elif magic == b'\x7fELF':
        report = analyze_elf(args.binary)
    else:
        print(f"{Colors.FAIL}Unknown binary type{Colors.ENDC}")
        sys.exit(1)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{Colors.BOLD}{Colors.OKCYAN}[*] Analysis report for {args.binary}{Colors.ENDC}")
        print(f"Type: {report['type']}")
        print(f"Entry Point: {report['entry_point']}")
        print(f"Packed: {report['packer_detected']}")
        print(f"Sections: {len(report['sections'])}")
        for sec in report['sections']:
            print(f"  - {sec['name']} (entropy {sec['entropy']})")
        print(f"Imports (first 20):")
        for imp in report['imports'][:20]:
            print(f"  {imp}")
        print(f"Anti-debug: {report['anti_debug_indicators']}")
        if report.get('rop_gadgets'):
            print(f"ROP gadgets (sample):")
            for g in report['rop_gadgets'][:10]:
                print(f"  {g['offset']}: {g['asm']}")
        print(f"Strings (sample):")
        for s in report['strings'][:30]:
            print(f"  {s}")

if __name__ == "__main__":
    main()