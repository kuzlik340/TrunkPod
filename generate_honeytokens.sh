#!/bin/bash

set -Eeuo pipefail

source "$PROJECT_ROOT"/global_functions.sh

STATE_FILE_PODS="/run/trunkpod.d/trunkpod_pods_stage"

FIRST_NAMES_FILE="$PROJECT_ROOT"/honeytokens_db/firstnames.txt
PASSWORD_FILE="$PROJECT_ROOT"/honeytokens_db/passwords.txt

FIRST_COUNT=$(wc -l < $FIRST_NAMES_FILE)
PASSWORD_COUNT=$(wc -l < $PASSWORD_FILE)
OUT_DIR="$PROJECT_ROOT/honeytokens_db/generated"
mkdir -p "$OUT_DIR"
OUT_FILE_HUMAN="$OUT_DIR/tokens.txt"
OUT_FILE_JSON="$OUT_DIR/tokens.json"

while true; do
    read -rp "[?] Choose how much tokens you want to generate. Input number (default 50): " CHOICE

    if [[ -z "$CHOICE" ]]; then  # ENTER key
        number=50
        break
    fi

    if [[ "$CHOICE" =~ ^[0-9]+$ ]]; then
        number="$CHOICE"
        break
    else
        echo "Invalid choice. Please enter a positive integer."
    fi
done

save_tokens() {
    {
        echo "# Generated: $(date)"
        echo "# Count: ${#TOKEN_USERNAMES[@]}"
        echo ""
        for ((i = 0; i < ${#TOKEN_USERNAMES[@]}; i++)); do
            echo "--- Token $((i + 1)) ---"
            echo "User:     ${TOKEN_USERNAMES[$i]}"
            echo "Password: ${TOKEN_PASSWORDS[$i]}"
            echo "FAKE_KEY=${TOKEN_SECRETS[$i]}"
            echo ""
        done
    } > "$OUT_FILE_HUMAN"

    print_success "Saved ${#TOKEN_USERNAMES[@]} tokens in human readable format in ${BLUE}$OUT_FILE_HUMAN${NC}"
}

save_tokens_json() {
    local json="[]"
    for ((i = 0; i < ${#TOKEN_USERNAMES[@]}; i++)); do
        json=$(jq \
            --arg u "${TOKEN_USERNAMES[$i]}" \
            --arg p "${TOKEN_PASSWORDS[$i]}" \
            --arg k "${TOKEN_SECRETS[$i]}" \
            '. += [{"username": $u, "password": $p, "fake_key": $k}]' \
            <<< "$json")
    done
    echo "$json" > "$OUT_FILE_JSON"
    print_success "Saved tokens in JSON format for pyhton script in ${BLUE}$OUT_FILE_JSON${NC}"
}


generate_token() {
    # Pick random name pair
    username=$(sed -n "$((RANDOM % FIRST_COUNT + 1))p" $FIRST_NAMES_FILE | tr -d '[:space:]')
    pswd=$(sed -n "$((RANDOM % PASSWORD_COUNT + 1))p" $PASSWORD_FILE | tr -d '[:space:]')


    # Generate a fake secret (40 random base64-like chars)
    secret=$(tr -dc 'A-Za-z0-9+/' < /dev/urandom 2>/dev/null | head -c 40; true)

    TOKEN_USERNAMES+=("$username")
    TOKEN_PASSWORDS+=("$pswd")
    TOKEN_SECRETS+=("$secret")

    print_info "User: $username"
    print_info "Password: $pswd"
    print_info "FAKE_KEY=$secret\n"
}

gen_by_number() {
    # Clear previous batch before regenerating
    TOKEN_USERNAMES=()
    TOKEN_PASSWORDS=()
    TOKEN_SECRETS=()

    for ((i = 1; i <= number; i++)); do
        generate_token
    done
}

gen_by_number


while true; do
    read -rp "[?] Regenerate tokens? [y/N] " CHOICE
    
    if [[ -z "$CHOICE" ]]; then # ENTER key
        CHOICE="n"
    fi

    # Normalize to lowercase
    CHOICE="${CHOICE,,}"

    case "$CHOICE" in
        n) 
            save_tokens_json
            save_tokens
	        break;
            ;;
        y)
            gen_by_number
	        ;;
        *)
            echo "Invalid choice. Please enter k, o, or m."
            ;;
    esac
done