#!/bin/bash
cp "$PROJECT_ROOT"/fluent-bit.conf /etc/fluent-bit
podman run -d \
  --replace \
  --name fluent-bit \
  -v /var/lib/containers/storage:/containers:ro \
  -v /var/log:/var/log \
  -v /etc/fluent-bit/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro \
  docker.io/fluent/fluent-bit:latest \
  -c /fluent-bit/etc/fluent-bit.conf
