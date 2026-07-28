#!/bin/bash

set -uo pipefail

source "$PROJECT_ROOT"/build_services/base_functions.sh
source "$PROJECT_ROOT"/global_functions.sh

trap rollback ERR

print_info "Creating base image" 

print_logfile_message 

ctr=$(buildah from debian:stable-slim)

#TODO fix command
run_buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr" 
print_info "Running update of base image. This will take some time..." 
run_buildah run --network host "$ctr" -- bash -c "
    apt-get update &&
    apt-get install -y --no-install-recommends \
        bash ca-certificates supervisor \
        python3 python3-pip python3-virtualenv python3.13-venv \
        openssh-server openssl \
        && apt-get clean && rm -rf /var/lib/apt/lists/*
"
run_buildah run "$ctr" virtualenv try-twisted
run_buildah run --network host "$ctr" /try-twisted/bin/pip install twisted[all] bcrypt cryptography
if podman image exists localhost/honeypot-base:latest; then
    podman image rm -f localhost/honeypot-base:latest > /dev/null
fi
run_buildah commit --rm "$ctr" honeypot-base:latest
print_success "Base image created" 
