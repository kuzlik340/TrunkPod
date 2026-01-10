#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR"/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}login_server${NC} service into your $IMAGE_NAME"

print_info "Creating /app directory for login service"
run_buildah run "$ctr" mkdir -p /app
print_info "Copying login_page.py"
run_buildah copy "$ctr" "$SCRIPT_DIR"/python_scripts/login_page.py /app/login_page.py

print_success "${YELLOW}login_server${NC} service was added to $IMAGE_NAME"
