#!/bin/bash

HASH_DIR=/run/honeybridge.d/hashes.txt

sha1sum build_services/build_base.sh 
sha1sum configs/network.yaml
sha1sum configs/honeypots.yaml