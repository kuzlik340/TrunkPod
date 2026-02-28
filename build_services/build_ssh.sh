#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}SSH${NC} service into your $IMAGE_NAME"

print_info "Copying python script for ${YELLOW}SSH${NC} service"
run_buildah run "$ctr" mkdir -p /ssh
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/json_formatter.py /ssh/json_formatter.py
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/ssh.py /ssh/ssh.py

print_success "${YELLOW}SSH${NC} service was added to $IMAGE_NAME"



