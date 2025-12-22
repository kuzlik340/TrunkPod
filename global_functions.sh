#!/bin/bash
HONEYPOT_CONF="configs/honeypots.yaml"
NETWORK_CONF="configs/network.yaml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[0;35m'
NC='\033[0m' 

yq_safe() {
    local result
    if ! result=$(yq "$@" 2>/dev/null); then
        print_error "YQ failed: check if config files are valid YAML"
        exit 1
    fi
    echo "$result"
}

print_stage() {
    local total_width=100
    local text="$*"
    local text_len=${#text}
    local padding=$(( total_width - text_len - 2 ))
    local left_pad=$(( padding / 2 ))
    local right_pad=$(( padding - left_pad ))
    local left_fill=$(printf "%*s" "$left_pad" "" | tr ' ' '=')
    local right_fill=$(printf "%*s" "$right_pad" "" | tr ' ' '=')
    echo -e "${left_fill} ${PURPLE}$*${NC} ${right_fill}"
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
