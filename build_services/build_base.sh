#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
cd "$SCRIPT_DIR"

source base_functions.sh

trap rollback ERR 

echo "[*] Creating base image"

print_logfile_message
ctr=$(buildah from debian:stable-slim)

#TODO fix command
run_buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr" 
#TODO  WHY works only with rc=
echo "[*] Running update of base image" 
run_buildah run "$ctr" -- bash -c "
    apt-get update &&
    apt-get install -y --no-install-recommends \
        bash sudo ca-certificates supervisor \
        python3 python3-pip \
        openssh-server \
        && apt-get clean && rm -rf /var/lib/apt/lists/*
"
run_buildah run "$ctr" useradd -m -s /bin/bash -u 1000 -G sudo admin
run_buildah run "$ctr" bash -c "echo 'admin:admin' | chpasswd"
run_buildah commit "$ctr" honeypot-base
echo "[+] Base image created"
