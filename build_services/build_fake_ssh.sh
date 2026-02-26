#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}FAKE_SSH${NC} service into your $IMAGE_NAME"

print_info "Copying python script for fake_ssh"
run_buildah run "$ctr" mkdir -p /app
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/fake_ssh.py /app/fake_ssh.py

print_success "${YELLOW}FAKE_SSH${NC} service was added to $IMAGE_NAME"



