#!/bin/bash

DOMAIN=$1
OUTPUT="dns_recon_${DOMAIN}.txt"
if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

echo "[*] Starting ultimate DNS recon on $DOMAIN" | tee -a $OUTPUT

# A, AAAA, MX, NS, TXT, SOA, CNAME
for type in A AAAA MX NS TXT SOA CNAME; do
    echo -e "\n[+] $type records:" | tee -a $OUTPUT
    dig $DOMAIN $type +short | tee -a $OUTPUT
done

# Zone transfer attempt
echo -e "\n[+] Attempting AXFR (zone transfer)" | tee -a $OUTPUT
for ns in $(dig $DOMAIN NS +short); do
    echo "  Trying $ns" | tee -a $OUTPUT
    dig @$ns $DOMAIN AXFR +short | tee -a $OUTPUT
done

# Reverse DNS for subnet
echo -e "\n[+] Reverse DNS on common IP ranges" | tee -a $OUTPUT
for ip in $(dig $DOMAIN A +short); do
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        subnet=$(echo $ip | cut -d. -f1-3)
        for i in {1..254}; do
            ptr=$(dig -x $subnet.$i +short)
            if [ ! -z "$ptr" ]; then
                echo "$subnet.$i -> $ptr" | tee -a $OUTPUT
            fi
        done
    fi
done

# DNSSEC check
echo -e "\n[+] DNSSEC status:" | tee -a $OUTPUT
dig $DOMAIN DNSKEY +short | tee -a $OUTPUT

# CAA records
echo -e "\n[+] CAA records:" | tee -a $OUTPUT
dig $DOMAIN CAA +short | tee -a $OUTPUT

echo "[+] Recon complete. Output saved to $OUTPUT"