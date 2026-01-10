#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR"/base_functions.sh
trap rollback ERR 
