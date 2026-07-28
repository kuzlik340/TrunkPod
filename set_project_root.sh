#!/bin/bash

# ===================================================
# Sets PROJECT_ROOT to the project's root directory,|
# allowing TrunkPod commands to be run from any     |
# working directory.                                |
# ===================================================

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_ROOT