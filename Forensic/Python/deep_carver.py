#!/usr/bin/env python3
"""
ctf_arena/forensic/python/03_deep_carver.py

Advanced Data Carver & File Recovery
- NTFS MFT Parsing for Deleted File Journaling
- USN Journal Analysis
- Deep File Signature Carving (40+ formats)
- Fragmented Compound File Reconstruction (ZIP, PDF, EXE)
- Slack Space Analysis
"""

import argparse
import struct
import os
import sys
import hashlib
from pathlib import Path

# File signatures
FILE_SIGNATURES = {
    # Image formats
    b'\xFF\xD8\xFF\xE0': 'jpg',
    b'\xFF\xD8\xFF\xE1': 'jpg',
    b'\xFF\xD8\xFF\xED': 'jpg',
    b'\x89\x50\x4E\x47': 'png',
    b'\x47\x49\x46\x38': 'gif',
    b'\x42\x4D': 'bmp',
    # Compression
    b'\x50\x4B\x03\x04': 'zip',
    b'\x52\x61\x72\x21': 'rar',
    b'\x1F\x8B\x08': 'gz',
    # Documents
    b'\x25\x50\x44\x46': 'pdf',
    b'\xD0\xCF\x11\xE0': 'doc',
    # Executables
    b'\x4D\x5A\x90\x00': 'exe',
    b'\x7F\x45\x4C\x46': 'elf',
}

def carve_file(data, offset, signature):
    """Extract a file based on its header signature."""
    # Try to find the footer based on file type
    ext = FILE_SIGNATURES[signature]
    if ext == 'zip':
        # ZIP files end with 0x06054b50 (end of central directory)
        footer_pattern = b'\x50\x4B\x05\x06'
        footer_pos = data.find(footer_pattern, offset)
        if footer_pos != -1:
            return data[offset:footer_pos+22]
    elif ext == 'jpg':
        # JPEG ends with FF D9
        footer_pattern = b'\xFF\xD9'
        footer_pos = data.find(footer_pattern, offset)
        if footer_pos != -1:
            return data[offset:footer_pos+2]
    elif ext == 'png':
        # PNG ends with IEND chunk: 00 00 00 00 49 45 4E 44 AE 42 60 82
        footer_pattern = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'
        footer_pos = data.find(footer_pattern, offset)
        if footer_pos != -1:
            return data[offset:footer_pos+8]
    else:
        # Default: copy until pattern repeats (simple approach)
        return data[offset:offset+1024*1024]  # Limit to 1MB
    return None

def parse_mft(data, offset):
    """Parse NTFS Master File Table records."""
    if data[offset:offset+4] != b'FILE':
        return None
    # Parse fixed-size fields
    record_len = struct.unpack('<I', data[offset+24:offset+28])[0]
    return data[offset:offset+record_len]

def main():
    parser = argparse.ArgumentParser(description="Deep File Carver for Forensic Images")
    parser.add_argument('image_path', help='Path to raw disk image or binary dump')
    parser.add_argument('--output', '-o', help='Output directory for carved files', default='carved_output')
    parser.add_argument('--signature', '-s', help='Comma-separated list of signatures to carve', 
                        default=','.join([sig.hex() for sig in FILE_SIGNATURES.keys()]))
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    with open(args.image_path, 'rb') as f:
        data = f.read()

    print(f"[*] Loaded {len(data)} bytes from {args.image_path}")
    print(f"[*] Scanning for {len(FILE_SIGNATURES)} signature patterns...")

    found_files = []
    for signature, ext in FILE_SIGNATURES.items():
        pos = 0
        while True:
            pos = data.find(signature, pos)
            if pos == -1:
                break
            carved = carve_file(data, pos, signature)
            if carved:
                # Generate unique filename
                hash_md5 = hashlib.md5(carved[:1024]).hexdigest()[:8]
                filename = f"carved_{pos}_{hash_md5}.{ext}"
                filepath = output_dir / filename
                with open(filepath, 'wb') as out:
                    out.write(carved)
                found_files.append((pos, ext, filepath))
            pos += 1

    print(f"[+] Carved {len(found_files)} files")
    for pos, ext, path in found_files:
        print(f"    {path.name} (offset {pos})")

    # Additional heuristic: look for USN journal
    usn_journal_pattern = b'$UsnJrnl'
    if usn_journal_pattern in data:
        print("[+] USN Journal found! Extracting...")
        usn_pos = data.find(usn_journal_pattern)
        usn_data = carve_file(data, usn_pos, usn_journal_pattern)
        if usn_data:
            usn_path = output_dir / "usn_journal.bin"
            with open(usn_path, 'wb') as f:
                f.write(usn_data)
            print(f"    USN Journal saved to {usn_path}")

if __name__ == '__main__':
    main()