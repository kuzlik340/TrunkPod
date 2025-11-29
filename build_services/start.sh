#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
cd "$SCRIPT_DIR"
IMAGE_NAME=$1
LOGFILE="/var/log/honeybridge_build.log"

services=("${@:2}")

echo "[*] Starting Buildah build: $IMAGE_NAME"
ctr=$(buildah from localhost/honeypot-base)
buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr"
./build_"${services[0]}".sh $IMAGE_NAME $ctr ${services[@]:1}


