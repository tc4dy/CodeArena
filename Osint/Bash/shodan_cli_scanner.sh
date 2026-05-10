#!/bin/bash
# Needs: shodan installed and API key set

TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain|ip|search_query>"
    exit 1
fi

OUTDIR="shodan_output_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTDIR

echo "[*] Shodan OSINT on $TARGET"

# If domain, get IPs first
if [[ $TARGET =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo "[*] Resolving domain: $TARGET"
    for ip in $(dig +short $TARGET); do
        echo "  IP: $ip"
        shodan host $ip > $OUTDIR/${ip}.txt
    done
else
    shodan host $TARGET > $OUTDIR/${TARGET}.txt
fi

# General search
shodan search "$TARGET" --limit 100 --fields ip_str,port,org,hostnames > $OUTDIR/search_results.csv

# Count open ports
echo "[*] Top open ports:"
shodan stats $TARGET --facets port

echo "[+] Results saved in $OUTDIR"