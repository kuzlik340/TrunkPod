#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
cd "$SCRIPT_DIR"
source base_functions.sh
trap rollback ERR

IMAGE_NAME=$1

services=("${@:2}")

echo "[*] Starting Buildah build: $IMAGE_NAME"
ctr=$(buildah from localhost/honeypot-base 2>/dev/null)
run_buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr"
trap - ERR
./build_"${services[0]}".sh $IMAGE_NAME $ctr ${services[@]:1}


