#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR"/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}FAKE_SSH${NC} service into your $IMAGE_NAME"

print_info "Copying python script for login page"
run_buildah run "$ctr" mkdir -p /app
run_buildah copy "$ctr" "$SCRIPT_DIR"/python_scripts/fake_ssh.py /app/fake_ssh.py #TODO rm new configured supervisord

print_success "${YELLOW}FAKE_SSH${NC} service was added to $IMAGE_NAME"



