#!/bin/bash

DOMAIN=$1
if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

OUTFILE="wayback_${DOMAIN}_$(date +%Y%m%d).txt"
echo "[*] Fetching Wayback Machine URLs for $DOMAIN"

# Wayback CDX API
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey" > $OUTFILE

# Also get unique
sort -u $OUTFILE -o $OUTFILE

COUNT=$(wc -l < $OUTFILE)
echo "[+] Found $COUNT unique URLs" | tee -a $OUTFILE

# Filter interesting extensions
echo "[*] Filtering interesting files: .sql, .bak, .env, .git, .config"
grep -E '\.(sql|bak|env|git|config|json|xml|log|key|pem)$' $OUTFILE > wayback_interesting_${DOMAIN}.txt

echo "[+] Done. Outputs: $OUTFILE and wayback_interesting_${DOMAIN}.txt"