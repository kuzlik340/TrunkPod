#!/bin/bash

podman run -d --name "$1" \
  -v /var/log/honeybridge/$1:/var/log/honeypot_logs \
  --hostname debian \
  --network none \
  --tmpfs /tmp:rw,size=64m \
  --read-only=false \
  $1:latest
