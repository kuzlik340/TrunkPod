#!/bin/bash

# ==============================================
# Module that runs installation of the tools.  |
# that will be used during honeypots deploy.   |
# ==============================================

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR"/global_functions.sh

install_package () {
    if ! dpkg -s "$1" &>/dev/null; then
        installed=1
        print_info "Installing $1"
        echo ""
        apt install -y "$1"
    fi
}
print_info "Checking tools"

installed=0

install_package podman
install_package arping
install_package yq
install_package python3

if [ "$installed" -eq 1 ]; then
    print_success "Tools are installed"
else
    print_info "Tools are ${GREEN}already installed${NC}"
fi
echo ""