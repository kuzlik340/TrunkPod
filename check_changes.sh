#!/bin/bash

# ================================================
# Module for detecting changes in required files.|
# If any file has been modified, configuration   |
# will be re-run from scratch.                   |
# ================================================


source global_functions.sh

HASH_FILE=/run/honeybridge.d/hashes.txt
TMP_FILE=$(mktemp)

changed=0
rebuild_base=0

FILES=(
    "build_services/build_base.sh"
    "configs/network.yaml"
    "configs/honeypots.yaml"
)

# First run: create the hash file and insert hashes
if [[ ! -f "$HASH_FILE" ]]; then
    for file in "${FILES[@]}"; do
        sha1sum "$file" >> "$HASH_FILE"
    done
    exit 2     # base rebuild on first run
fi

while read -r stored_hash stored_path; do
    
    if [[ ! -f "$stored_path" ]]; then
        print_error "Missing file: $stored_path"
        exit 50 # Error code
    fi

    current_hash="$(sha1sum "$stored_path" | awk '{print $1}')"

    if [[ "$stored_hash" != "$current_hash" ]]; then
        print_info "Changed: $stored_path"
        changed=1

        if [[ "$stored_path" == "build_services/build_base.sh" ]]; then
            rebuild_base=1
        fi

        echo "$current_hash  $stored_path" >> "$TMP_FILE"
    else
        echo "$stored_hash  $stored_path" >> "$TMP_FILE"
    fi

done < "$HASH_FILE"
mv "$TMP_FILE" "$HASH_FILE"

# If the base_image.sh was changed
if [[ $rebuild_base -eq 1 ]]; then
    exit 2
fi
exit $changed