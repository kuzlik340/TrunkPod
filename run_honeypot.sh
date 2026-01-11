#!/bin/bash

podman run -d --name "$1" \
  --hostname debian \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --network none \
  --tmpfs /app:rw,size=16m \
  --tmpfs /tmp:rw,size=64m \
  --tmpfs /run:rw,size=16m \
  --tmpfs /var/log:rw,size=64m \
  --read-only \
  --pids-limit 50 \
  "$1":latest
