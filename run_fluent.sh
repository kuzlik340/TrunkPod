#!/bin/bash
podman run -d \
  --replace \
  --name fluent-bit \
  -v /var/lib/containers/storage:/containers:ro \
  -v /var/log:/var/log \
  -v "$PROJECT_ROOT"/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro \
  docker.io/fluent/fluent-bit:latest \
  -c /fluent-bit/etc/fluent-bit.conf

