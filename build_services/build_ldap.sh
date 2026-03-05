#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}LDAP${NC} service into your $IMAGE_NAME"

print_info "Copying python script for ${YELLOW}LDAP${NC} service"
run_buildah run "$ctr" mkdir -p /services/ldap
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/json_formatter.py /services/ldap/json_formatter.py
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/honeytokens.py /services/ldap/honeytokens.py
run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/python_scripts/ldap.py /services/ldap/ldap.py

print_success "${YELLOW}LDAP${NC} service was added to $IMAGE_NAME"



