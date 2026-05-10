#!/bin/bash

echo -e "\033[95m"
cat << "EOF"
  ____                  __
 / ___|  __ _  ___ ___  / _| __ _ _ __
| |     / _` |/ __/ _ \| |_ / _` | '__|
| |___ | (_| | (_| (_) |  _| (_| | |
 \____| \__,_|\___\___/|_|  \__,_|_|
EOF
echo -e "\033[0mCaesar Cipher Brute-Forcer\n"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <ciphertext>"
    exit 1
fi

ciphertext=$(echo "$1" | tr '[:upper:]' '[:lower:]')
echo "Ciphertext: $ciphertext"
echo "-----------------------------------"

for shift in {1..25}; do
    plain=""
    for ((i=0; i<${#ciphertext}; i++)); do
        c=${ciphertext:$i:1}
        if [[ $c =~ [a-z] ]]; then
            ord=$(printf "%d" "'$c")
            new_ord=$((ord - shift))
            if [ $new_ord -lt 97 ]; then
                new_ord=$((new_ord + 26))
            fi
            new_char=$(printf "\\$(printf "%03o" "$new_ord")")
            plain+="$new_char"
        else
            plain+="$c"
        fi
    done
    printf "\033[93mShift %2d\033[0m: %s\n" "$shift" "$plain"
done