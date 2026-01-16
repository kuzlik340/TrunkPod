#!/bin/bash

podman run -d --name "$1" \
  --hostname debian \
  --security-opt no-new-privileges \
  --network none \
  --tmpfs /app:rw,size=16m \
  --tmpfs /tmp:rw,size=64m \
  --tmpfs /run:rw,size=16m \
  --tmpfs /var/log:rw,size=64m \
  --pids-limit 50 \
  "$1":latest
