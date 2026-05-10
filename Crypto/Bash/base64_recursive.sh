#!/bin/bash

echo -e "\033[95mRecursive Base64 Decoder\033[0m"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <base64_string>"
    exit 1
fi

data="$1"
level=0
while true; do
    echo -e "\033[93mLevel $level:\033[0m $data"
    decoded=$(echo "$data" | base64 -d 2>/dev/null)
    if [ $? -ne 0 ] || [ "$decoded" == "$data" ]; then
        break
    fi
    data="$decoded"
    ((level++))
done
echo -e "\033[92mFinal:\033[0m $data"