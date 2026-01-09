#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source base_functions.sh
trap rollback ERR 


print_info "Adding ${YELLOW}login_server${NC} service into your $IMAGE_NAME"

print_info "Creating /app directory for login service"
run_buildah run "$ctr" mkdir -p /app

print_info "Copying login_page.py"
run_buildah copy "$ctr" python_scripts/login_page.py /app/login_page.py

print_success "${YELLOW}login_server${NC} service was added to $IMAGE_NAME"
