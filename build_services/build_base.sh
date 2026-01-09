#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
cd "$SCRIPT_DIR"

source base_functions.sh
source ../global_functions.sh

trap rollback ERR 

print_info "Creating base image"

print_logfile_message
ctr=$(buildah from debian:stable-slim)

#TODO fix command
run_buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr" 
#TODO  WHY works only with rc=
print_info "Running update of base image. This will take some time..." 
run_buildah run "$ctr" -- bash -c "
    apt-get update &&
    apt-get install -y --no-install-recommends \
        bash sudo ca-certificates supervisor \
        python3 python3-pip python3-virtualenv \
        openssh-server \
        && apt-get clean && rm -rf /var/lib/apt/lists/*
"
run_buildah run "$ctr" virtualenv try-twisted
run_buildah run "$ctr" /try-twisted/bin/pip install twisted[all] bcrypt cryptography
run_buildah run "$ctr" useradd -m -s /bin/bash -u 1000 -G sudo admin
run_buildah run "$ctr" bash -c "echo 'admin:admin' | chpasswd"
run_buildah commit "$ctr" honeypot-base
run_buildah rm "$ctr"
print_success "Base image created"
