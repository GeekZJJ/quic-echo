#!/bin/bash

if ! test -d demo-scripts; then
    echo "call this script from the top-level directory"
    exit 1
fi

. demo-scripts/demo-magic/demo-magic.sh

DEMO_PROMPT="${GREEN}➜ ${CYAN}\W "

clear

pei 'tshark -o "tls.keylog_file: $PWD/keylog.txt" -i lo -Px -O quic -Y "udp.port == 5556"'

p ""
