#!/bin/bash
set -uo pipefail

IMAGE_NAME=$1
ctr=$2

source base_functions.sh
trap rollback ERR 
