#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}HTTP${NC} service into your $IMAGE_NAME"

print_info "Copying python script for ${YELLOW}HTTP${NC} service"
run_buildah run "$ctr" mkdir -p /http
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/http_server.py /http/http_server.py

print_success "${YELLOW}HTTP${NC} service was added to $IMAGE_NAME"
