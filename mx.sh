#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}
# TODO: get all MX, but losses original if CNAME chained
NMAP=/usr/local/bin/nmap

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

nmap_ext(){
    local nmap_ext=( ssh ssl smtp pop3 tls imap )
    local nmap_string=""
    for proto in "${nmap_ext[@]}"; do
        nmap_string+=" or (*${proto}* and (discovery or safe or auth))"
    done
    echo "${nmap_string}"
}

nmap_mx(){
    local mx=${1}
    local file=../mx/${mx}/nmap
    if [[ ! -f ${file}.nmap ]]; then
        sudo $NMAP -n \
             -PE -PS25,465 -PA25 -PP \
             -v -sTV --reason \
             -oA ${file} \
             -F \
             -6 \
             --resolve-all \
             --script='default or banner or fcrdns'"$(nmap_ext)" \
             ${mx}
    fi
}

dns_mx "${DOMAIN}" |
    while IFS='|' read -r host mx; do
        echo "${host} ${mx}"
        mkdir -p ../mx/${mx}
        upsert_in_file ../mx/${mx}/hosts ${host}
        nmap_mx ${mx}
    done
