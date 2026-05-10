#!/bin/bash
# Uses haveibeenpwned API (requires API key for v3)

EMAIL=$1
API_KEY=$2
if [ -z "$EMAIL" ] || [ -z "$API_KEY" ]; then
    echo "Usage: $0 <email> <hibp_api_key>"
    exit 1
fi

echo "[*] Checking $EMAIL against known breaches"

# HIBP v3
curl -s -H "hibp-api-key: $API_KEY" "https://haveibeenpwned.com/api/v3/breachedaccount/$EMAIL" | jq '.' > breaches_${EMAIL}.json

# Also check pastebin
curl -s -H "hibp-api-key: $API_KEY" "https://haveibeenpwned.com/api/v3/pasteaccount/$EMAIL" | jq '.' > pastes_${EMAIL}.json

if [ -s breaches_${EMAIL}.json ]; then
    echo "[!] Breaches found!" 
    cat breaches_${EMAIL}.json
else
    echo "[-] No breaches"
fi

# Alternative: use leak-lookup free API
echo "[*] Trying leak-lookup.com (free)"
curl -s -X POST https://leak-lookup.com/api/search -d "key=demo&type=email&query=$EMAIL" > leak_${EMAIL}.json

echo "[+] Results saved."