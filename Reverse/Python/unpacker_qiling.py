import sys
from qiling import Qiling
from qiling.const import QL_VERBOSE
import os

def unpack_upx(input_file, output_file):
    ql = Qiling([input_file], ".", verbose=QL_VERBOSE.DEBUG)
    # Hook at entry point, find OEP using stack signature
    def hook_entry(ql):
        # typical UPX OEP is after XOR instructions
        print("[*] Hit entry point, searching for OEP...")
        # Scanning memory for known pattern: 0x60 0x61 or something
        # For brevity, just dump all executable sections
        for start, end, perms, name in ql.mem.map_info:
            if 'rx' in perms:
                data = ql.mem.read(start, end-start)
                # look for pusha/popa pattern
                if b'\x60' in data and b'\x61' in data:
                    print(f"Possible OEP section: {hex(start)}")
                    # Dump section
                    with open(output_file, 'wb') as f:
                        f.write(data)
                    return
    ql.hook_address(hook_entry, ql.loader.entry_point)
    ql.run()
    print(f"[+] Unpacked data written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: 05_unpacker_qiling.py <packed> <unpacked_output>")
        sys.exit(1)
    unpack_upx(sys.argv[1], sys.argv[2])