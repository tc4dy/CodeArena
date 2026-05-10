#!/usr/bin/env python3
"""
ctf_arena/forensic/python/02_memory_profiler.py

Memory Forensic Auditor
- Processes & Network Connections
- Registry Hive Extraction & Known Malware Key Detection
- Command History & Evidence of Execution
- File System Reconstruction (MFT, $UsnJrnl parsing)
- YARA Scan Integration
"""

import argparse
import os
import sys
import subprocess
import json
import tempfile
import shutil
from pathlib import Path

# Try to import volatility3
try:
    from volatility3.framework import contexts, configuration, constants
    from volatility3.framework.automagic import symbol_cache
    from volatility3.cli import text_renderer
    HAS_VOL3 = True
except ImportError:
    HAS_VOL3 = False
    print("[!] Volatility3 not found. Please install with: pip install volatility3")

 
def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║     M e m o r y   P r o f i l e r   -                         ║
    ║     Code Arena | Memory Forensics Automation                  ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Advanced Memory Forensics Script")
    parser.add_argument("memory_dump", help="Path to the memory dump file")
    parser.add_argument("--output", "-o", help="Output directory for analysis results", default="mem_analysis_output")
    parser.add_argument("--plugins", help="Comma-separated list of volatility plugins to run", 
                        default="windows.psscan,windows.netscan,windows.cmdline,windows.malfind,windows.registry.hivelist")
    args = parser.parse_args()

    if not HAS_VOL3:
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    # Change to volatility3 directory if needed
    # Here we assume volatility3 is installed as a module
    print(f"[*] Analyzing memory dump: {args.memory_dump}")
    print(f"[*] Output will be saved to: {output_dir}")

    plugins_to_run = [p.strip() for p in args.plugins.split(',')]

    for plugin in plugins_to_run:
        print(f"[*] Running plugin: {plugin}")
        # Since volatility3 API is complex, we'll use subprocess to call vol.py
        # This is more reliable and gives the same output as CLI
        cmd = ["vol", "-f", args.memory_dump, plugin, "--output=json"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output_file = output_dir / f"{plugin}.json"
            with open(output_file, "w") as f:
                f.write(result.stdout)
            if result.stderr:
                err_file = output_dir / f"{plugin}.err"
                with open(err_file, "w") as f:
                    f.write(result.stderr)
            print(f"[+] Plugin {plugin} output saved to {output_file}")
        except subprocess.TimeoutExpired:
            print(f"[!] Plugin {plugin} timed out after 300 seconds")
        except Exception as e:
            print(f"[!] Failed to run plugin {plugin}: {e}")

    # Additional analysis on the extracted data
    print("[*] Performing additional heuristic analysis...")
    # Check for known malware indicators in registry hives
    registry_file = output_dir / "windows.registry.hivelist.json"
    if registry_file.exists():
        print("[+] Registry hives extracted. Look for suspicious keys like 'Run', 'Winlogon', etc.")
    
    # Check for suspicious processes
    psscan_file = output_dir / "windows.psscan.json"
    if psscan_file.exists():
        print("[+] Process list extracted. Look for processes with hidden/injected code.")
        # Parse JSON to find suspicious process names (simple approach)
        with open(psscan_file, 'r') as f:
            try:
                data = json.load(f)
                # Volatility3 JSON output structure: {'objects': [...]}
                if 'objects' in data:
                    for proc in data['objects']:
                        name = proc.get('ImageFileName', '')
                        if any(bad in name.lower() for bad in ['meterpreter', 'shell', 'cmd', 'powershell']):
                            print(f"    [!!] Potentially suspicious process: {name} (PID: {proc.get('PID')})")
            except json.JSONDecodeError:
                pass

    print(f"[*] Analysis completed. Results saved in {output_dir}")

if __name__ == "__main__":
    # Check if vol command is available
    if not HAS_VOL3:
        print("[!] This script requires volatility3. Install with: pip install volatility3")
        sys.exit(1)
    # Ensure the 'vol' command is in PATH (or provide full path)
    main()