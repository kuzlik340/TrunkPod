#!/bin/bash

sudo podman run -d --name "$1" \
  --hostname debian \
  --network none \
  --tmpfs /tmp:rw,size=64m \
  --read-only=false \
  honeypot:latest
