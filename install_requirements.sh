#!/bin/bash

# ==============================================
# Module that runs installation of the tools.  |
# that will be used during honeypots deploy.   |
# ==============================================

source global_functions.sh

print_info "Checking tools"

installed=0
if ! dpkg -s podman &>/dev/null; then
    installed=1
    print_info "Installing podman"
    echo ""
    sudo apt install -y podman
fi

if ! dpkg -s arping &>/dev/null; then
    installed=1
    print_info "Installing arping"
    echo ""
    sudo apt install -y arping
fi

if ! dpkg -s yq &>/dev/null; then
    installed=1
    print_info "Installing yq"
    echo ""
    sudo apt install -y yq
fi

if ! dpkg -s python3 &>/dev/null; then
    installed=1
    print_info "Installing python3"
    echo ""
    sudo apt install -y python3
fi

if [ "$installed" -eq 1 ]; then
    print_success "Tools are installed"
else
    print_info "Tools are ${GREEN}already installed${NC}"
fi
echo ""