#!/bin/bash

echo -e "\033[95mXOR Bruteforce (single-byte key)\033[0m"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <hex string>"
    exit 1
fi

hex="$1"
bytes=$(echo "$hex" | sed 's/../& /g')
best_score=-1
best_plain=""
best_key=0

for key in {0..255}; do
    plain=""
    for byte in $bytes; do
        val=$((0x$byte))
        dec=$((val ^ key))
        if [ $dec -ge 32 ] && [ $dec -le 126 ]; then
            plain+=$(printf "\\$(printf "%03o" "$dec")")
        else
            plain+="."
        fi
    done
    score=$(echo "$plain" | grep -o '[A-Za-z ]' | wc -l)
    if [ $score -gt $best_score ]; then
        best_score=$score
        best_plain="$plain"
        best_key=$key
    fi
done

echo -e "\033[92mBest key: $best_key (0x$(printf "%02x" $best_key))\033[0m"
echo -e "\033[92mPlaintext: $best_plain\033[0m"