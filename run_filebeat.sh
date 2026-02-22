#!/bin/bash
podman run -d \
  --replace \
  --name filebeat \
  --user=root \
  -v "$PROJECT_ROOT"/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro \
  -v /var/log:/var/log:ro \
  -v filebeat-data:/usr/share/filebeat/data:rw \
  docker.elastic.co/beats/filebeat:9.3.0 \
  filebeat -e --strict.perms=false

