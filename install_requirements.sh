#!/bin/bash

# ==============================================
# Module that runs installation of the tools.  |
# that will be used during honeypots deploy.   |
# ==============================================

set -Eeuo pipefail

source "$PROJECT_ROOT"/global_functions.sh

install_package () {
    if ! dpkg -s "$1" &>/dev/null; then
        installed=1
        print_info "Installing $1"
        echo ""
        apt install -y "$1" > /dev/null 2>&1
    fi
}
print_info "Checking tools"

installed=0

install_package podman
install_package arping
install_package yq
install_package jq
install_package python3
install_package curl

FIRSTNAMES="$PROJECT_ROOT/honeytokens_db/firstnames.txt"
PASSWORDS="$PROJECT_ROOT/honeytokens_db/passwords.txt"

# Create the directory if it doesn't exist yet
mkdir -p "$PROJECT_ROOT/honeytokens_db"

if [ ! -f "$FIRSTNAMES" ]; then
    print_info "Downloading firstnames..."
    curl -sS -o "$FIRSTNAMES" \
        https://raw.githubusercontent.com/dominictarr/random-name/master/first-names.txt 
fi

if [ ! -f "$PASSWORDS" ]; then
    print_info "Downloading firstnames..."
    curl -sS -o "$PASSWORDS" \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/Lizard-Squad.txt
fi

    

if [ "$installed" -eq 1 ]; then
    print_success "Tools are installed"
else
    print_info "Tools are ${GREEN}already installed${NC}"
fi
echo ""