#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}RDP${NC} service into your $IMAGE_NAME"

run_buildah run "$ctr" mkdir -p /rdp
run_buildah run "$ctr" python3 -m venv /rdp/venv
print_info "Copying python script for ${YELLOW}RDP${NC} service"
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/rdp /rdp
print_info "Installing libraries for ${YELLOW}RDP${NC} service"
run_buildah run "$ctr" /rdp/venv/bin/pip install -r /rdp/requirements.txt

print_success "${YELLOW}RDP${NC} service was added to $IMAGE_NAME"