#!/usr/bin/env python3
"""
ctf_arena/forensic/python/01_pcap_assembler.py

Advanced PCAP Forensic Toolkit
- TCP Stream Reassembly
- Automatic Base64 Fragment Detection & Joining
- File Carving from HTTP/FTP Transfers
- Entropy Analysis to Find Encrypted Payloads
- Hidden Key Extraction (AES, RSA patterns)
"""

import argparse
import base64
import hashlib
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    import numpy as np
except ImportError as e:
    print(f"[!] Missing required library: {e}. Please install: pip install scapy numpy")
    sys.exit(1)

def print_banner():
    banner = """

     ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
    ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
    ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌
    ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌
    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌
    ▐░█▀▀▀▀█░█▀▀ ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ 
    ▐░▌     ▐░▌  ▐░▌       ▐░▌          ▐░▌▐░▌       ▐░▌▐░▌          
    ▐░▌      ▐░▌ ▐░▌       ▐░▌ ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌          
    ▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌          
     ▀         ▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀           

    PCAP Forensic Toolkit v2.0 | Code Arena
    """
    print(banner)

# ======================== Helper Functions ========================
def entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    return entropy

def extract_base64_fragments(payload: bytes) -> list:
    """Extract potential base64 fragments from raw bytes."""
    ascii_text = payload.decode('ascii', errors='ignore')
    # Match base64 patterns (standard and URL-safe)
    b64_pattern = r'[A-Za-z0-9+/=]{20,}'
    fragments = re.findall(b64_pattern, ascii_text)
    return fragments

def attempt_base64_join(fragments: list) -> str:
    """Try to join base64 fragments and decode."""
    full_b64 = ''.join(fragments)
    # Remove any non-base64 characters
    clean_b64 = re.sub(r'[^A-Za-z0-9+/=]', '', full_b64)
    try:
        decoded = base64.b64decode(clean_b64).decode('utf-8', errors='ignore')
        return decoded
    except:
        return None

def extract_keys(payload: bytes) -> dict:
    """Heuristic search for crypto keys (AES, RSA patterns)."""
    keys = {}
    ascii_text = payload.decode('ascii', errors='ignore')
    # AES key patterns (32 hex chars = 128-bit, 64 hex chars = 256-bit)
    aes_128 = re.findall(r'[a-fA-F0-9]{32}', ascii_text)
    aes_256 = re.findall(r'[a-fA-F0-9]{64}', ascii_text)
    if aes_128:
        keys['AES-128'] = aes_128
    if aes_256:
        keys['AES-256'] = aes_256
    # PEM encoded RSA private key pattern
    if '-----BEGIN RSA PRIVATE KEY-----' in ascii_text:
        keys['RSA'] = 'PEM Private Key Found'
    return keys

def analyze_payload(payload: bytes, stream_id: int) -> dict:
    """Perform deep analysis on a single TCP payload."""
    result = {
        'stream_id': stream_id,
        'size': len(payload),
        'entropy': entropy(payload),
        'base64_fragments': extract_base64_fragments(payload),
        'keys': extract_keys(payload),
        'is_encrypted': entropy(payload) > 7.0  # Heuristic for encrypted/compressed data
    }
    if result['base64_fragments']:
        decoded_secret = attempt_base64_join(result['base64_fragments'])
        if decoded_secret:
            result['decoded_secret'] = decoded_secret
    return result

def reassemble_tcp_streams(packets):
    """Reassemble TCP streams based on src/dst IP and ports."""
    streams = defaultdict(list)
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            # Create a unique key for the stream (bidirectional)
            src = (pkt[IP].src, pkt[TCP].sport)
            dst = (pkt[IP].dst, pkt[TCP].dport)
            # Normalize stream key (always smaller first)
            key = tuple(sorted([src, dst]))
            streams[key].append(pkt[Raw].load)
    # Combine payloads in order (scapy already gives them in capture order)
    reassembled = {}
    for key, payloads in streams.items():
        reassembled[key] = b''.join(payloads)
    return reassembled

# ======================== Main Analysis Engine ========================
def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Advanced PCAP Forensic Analysis')
    parser.add_argument('pcap_file', help='Path to the PCAP file')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads for analysis')
    parser.add_argument('--output', '-o', help='Output directory for extracted files')
    args = parser.parse_args()

    print(f"[*] Loading PCAP file: {args.pcap_file}")
    try:
        packets = rdpcap(args.pcap_file)
    except Exception as e:
        print(f"[!] Failed to read PCAP: {e}")
        sys.exit(1)
    print(f"[+] Loaded {len(packets)} packets")

    # Reassemble TCP streams
    print("[*] Reassembling TCP streams...")
    streams = reassemble_tcp_streams(packets)
    print(f"[+] Found {len(streams)} unique TCP streams")

    # Analyze each stream
    stream_list = list(streams.items())
    results = []
    print(f"[*] Analyzing streams with {args.threads} threads...")
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_stream = {executor.submit(analyze_payload, payload, i): (key, i) 
                            for i, (key, payload) in enumerate(stream_list)}
        for future in as_completed(future_to_stream):
            key, stream_id = future_to_stream[future]
            try:
                result = future.result()
                results.append(result)
                print(f"    Stream {stream_id}: {result['size']} bytes | Entropy: {result['entropy']:.2f} | Encrypted: {result['is_encrypted']}")
                if result.get('decoded_secret'):
                    print(f"        [!!] Decoded Secret Found: {result['decoded_secret'][:100]}...")
                if result['keys']:
                    print(f"        [!!] Crypto Keys Found: {result['keys']}")
            except Exception as e:
                print(f"[!] Error analyzing stream {stream_id}: {e}")

    # Summary
    print("\n[+] Analysis Complete")
    print(f"    Total streams analyzed: {len(results)}")
    encrypted_streams = sum(1 for r in results if r['is_encrypted'])
    print(f"    High-entropy (likely encrypted/compressed) streams: {encrypted_streams}")
    streams_with_keys = sum(1 for r in results if r['keys'])
    print(f"    Streams containing crypto keys: {streams_with_keys}")
    streams_with_b64 = sum(1 for r in results if r['base64_fragments'])
    print(f"    Streams containing base64 fragments: {streams_with_b64}")

    # Optional: save extracted artifacts
    if args.output:
        import os
        os.makedirs(args.output, exist_ok=True)
        # Save reassembled streams
        for i, (key, payload) in enumerate(streams.items()):
            with open(os.path.join(args.output, f'stream_{i}.bin'), 'wb') as f:
                f.write(payload)
        # Save report
        with open(os.path.join(args.output, 'analysis_report.txt'), 'w') as f:
            for r in results:
                f.write(f"Stream {r['stream_id']}: entropy={r['entropy']:.2f}, encrypted={r['is_encrypted']}\n")
                if r.get('decoded_secret'):
                    f.write(f"  Secret: {r['decoded_secret']}\n")
                if r['keys']:
                    f.write(f"  Keys: {r['keys']}\n")
        print(f"[*] Artifacts saved to {args.output}")

if __name__ == '__main__':
    main()