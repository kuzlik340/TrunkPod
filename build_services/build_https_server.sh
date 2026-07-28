#!/bin/bash

set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}HTTPS${NC} service into your $IMAGE_NAME"

print_info "Copying python script for ${YELLOW}HTTPS${NC} service"
run_buildah run "$ctr" mkdir -p /services/https
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/json_formatter.py /services/https/json_formatter.py
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/honeytokens.py /services/https/honeytokens.py
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/https_server.py /services/https/https_server.py

print_success "${YELLOW}HTTPS${NC} service was added to $IMAGE_NAME"
