#!/bin/bash

set -uo pipefail

timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
touch "/var/log/honeybridge_build_$timestamp.log"
echo "/var/log/honeybridge_build_$timestamp.log" > build_services/log_file_path
