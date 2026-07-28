#!/bin/bash

# =================================================
# Global utility functions shared across multiple |
# modules. Most functions provide standardized    |
# output formatting and common helper routines.   |
# =================================================

HONEYPOT_CONF="$PROJECT_ROOT/configs/honeypots.yaml"
NETWORK_CONF="$PROJECT_ROOT/configs/network.yaml"

STATE_DIR="/run/trunkpod.d"  # Stores TrunkPod stage progress for safe restarts
STATE_FILE="/run/trunkpod.d/trunkpod_stage"
STATE_FILE_PODS="/run/trunkpod.d/trunkpod_pods_stage"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[0;35m'
NC='\033[0m' 


error=0
# Function with assign-by-reference method to make error handling
yq_safe() {
    local __outvar="$1"
    shift

    local out
    if ! out=$(yq "$@" 2>/dev/null); then
        print_error "YQ failed: invalid YAML"
        exit 1
    fi

    printf -v "$__outvar" '%s' "$out"
}

print_stage() {
    local total_width
    total_width=$(tput cols)
    local text="$*"
    local text_len=${#text}
    local padding=$(( total_width - text_len - 2 ))
    local left_pad=$(( padding / 2 ))
    local right_pad=$(( padding - left_pad ))
    local left_fill
    local right_fill
    left_fill=$(printf "%*s" "$left_pad" "" | tr ' ' '=')
    right_fill=$(printf "%*s" "$right_pad" "" | tr ' ' '=')
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
