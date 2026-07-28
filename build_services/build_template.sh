#!/bin/bash

# ======================================================
# Template for adding new services to honeypot images. |
# Use this structure to keep build scripts consistent, |
# readable, and easier to maintain.                    |
#                                                      |
# Naming convention:                                   |
#   Name the script as build_<service>.sh, where       |
#   <service> matches the service name defined in      |
#   honeypots.yaml.                                    |
# ======================================================

set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 
