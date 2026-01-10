#!/bin/bash

# ================================================
# Module for detecting changes in required files.|
# If any file has been modified, configuration   |
# will be re-run from scratch.                   |
# ================================================
# Returns 2 if rebuild base should be done, 1 if |
# cold boot, 3 if config changed, 50 if files are|
# missing.                                       |
# ================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR"/global_functions.sh

HASH_FILE=/run/honeybridge.d/hashes.txt
TMP_FILE=$(mktemp)


exit_code=0

FILES=(
    "build_services/build_base.sh" # Always keep at the start of list
    "configs/network.yaml"
    "configs/honeypots.yaml"
)

# First run: create the hash file and insert hashes
if [[ ! -f "$HASH_FILE" ]]; then
    for file in "${FILES[@]}"; do
        sha1sum "$file" >> "$HASH_FILE"
    done
    exit 1     # cold boot
fi

while read -r stored_hash stored_path; do
    
    if [[ ! -f "$stored_path" ]]; then
        print_error "Missing file: $stored_path"
        exit 50 # Error code
    fi

    current_hash="$(sha1sum "$stored_path" | awk '{print $1}')"

    if [[ "$stored_hash" != "$current_hash" ]]; then
        print_info "Changed: $stored_path"
        exit_code=3

        if [[ "$stored_path" == "build_services/build_base.sh" ]]; then
            exit_code=2
        fi

        echo "$current_hash  $stored_path" >> "$TMP_FILE"
    else
        echo "$stored_hash  $stored_path" >> "$TMP_FILE"
    fi

done < "$HASH_FILE"
mv "$TMP_FILE" "$HASH_FILE"

exit $exit_code
