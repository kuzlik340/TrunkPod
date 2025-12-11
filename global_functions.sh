#!/bin/bash
HONEYPOT_CONF="configs/honeypots.yaml"
NETWORK_CONF="configs/network.yaml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[0;35m'
NC='\033[0m' 

print_stage() {
    echo -e "================================= ${PURPLE}$*${NC} ================================="
}

print_warning() {
    echo -e "[${YELLOW}!${NC}] ${YELLOW}WARNING:${NC} $*"
}

print_error() {
    echo -e "[${RED}!${NC}] ${RED}ERROR:${NC} $*"
}

print_success() {
    echo -e "[${GREEN}*${NC}] ${GREEN}SUCCESS:${NC} $*"
}

print_info() {
    echo -e "[${PURPLE}*${NC}] ${PURPLE}INFO:${NC} $*"
}

print_deletion() {
    echo -e "[${RED}-${NC}] $*"
}
