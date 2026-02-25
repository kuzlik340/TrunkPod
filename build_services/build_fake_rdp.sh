#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}FAKE_RDP${NC} service into your $IMAGE_NAME"

run_buildah run "$ctr" mkdir -p /rdp
run_buildah run "$ctr" python3 -m venv /rdp/venv
print_info "Copying python script for fake_rdp"
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/fake_rdp /rdp
print_info "Installing libraries for fake_rdp"
run_buildah run "$ctr" /rdp/venv/bin/pip install -r /rdp/requirements.txt

print_success "${YELLOW}FAKE_RDP${NC} service was added to $IMAGE_NAME"