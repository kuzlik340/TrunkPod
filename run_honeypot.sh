#!/bin/bash

# ====================================================
# Main module for starting pre-built pods/containers.|
# Configure instance settings here to make them      |
# more restrictive or secure.                        |
# ====================================================

mkdir -p /var/log/trunkpod/"$1"

podman run -d --name "$1" --replace \
  --log-driver=k8s-file \
  --hostname debian \
  --security-opt no-new-privileges \
  --cap-drop=all \
  --cap-add=NET_BIND_SERVICE \
  --network none \
  -v /var/log/trunkpod/"$1":/log:rw \
  --read-only=false \
  --tmpfs /tmp:rw,size=16m \
  --tmpfs /run:rw,size=16m \
  --tmpfs /var/log:rw,size=64m \
  --tmpfs /services:rw,size=16m \
  --pids-limit 50 \
  "$1":latest
