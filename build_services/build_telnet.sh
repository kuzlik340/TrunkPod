#!/bin/bash

set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}TELNET${NC} service into your $IMAGE_NAME"

print_info "Copying python script for ${YELLOW}TELNET${NC} service"
run_buildah run "$ctr" mkdir -p /services/telnet
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/json_formatter.py /services/telnet/json_formatter.py
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/honeytokens.py /services/telnet/honeytokens.py
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/telnet.py /services/telnet/telnet.py

print_success "${YELLOW}TELNET${NC} service was added to $IMAGE_NAME"



