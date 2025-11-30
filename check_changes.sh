#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

HASH_FILE=/run/honeybridge.d/hashes.txt
TMP_FILE=$(mktemp)

changed=0

# First-run: create the hash file and insert hashes
if [[ ! -f "$HASH_FILE" ]]; then
    sha1sum build_services/build_base.sh >> $HASH_FILE
    sha1sum configs/network.yaml >> $HASH_FILE
    sha1sum configs/honeypots.yaml >> $HASH_FILE
    exit 0
fi

while read -r stored_hash stored_path; do
    if [[ -f "$stored_path" ]]; then
        current_hash=$(sha1sum "$stored_path" | awk '{print $1}')
        if [[ "$stored_hash" != "$current_hash" ]]; then
            echo -e "[*] ${GREEN}CHANGED:${NC} $stored_path"
            echo "$current_hash  $stored_path" >> "$TMP_FILE"
            changed=1
        else
            # keep the old line
            echo "$stored_hash  $stored_path" >> "$TMP_FILE"
        fi
    else
        echo -e "[!] ${RED}MISSING FILE:${NC} $stored_path"
    fi
done < "$HASH_FILE"
mv "$TMP_FILE" "$HASH_FILE"
exit $changed