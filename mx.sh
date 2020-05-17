#!/bin/bash

set -exuo pipefail

# TODO: get all MX, but losses original if CNAME chained
NMAP=/usr/local/bin/nmap

source ${HOME}/projects/sec/autoaim/helpers.sh

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

if compgen -G data/domains/resolved/short_mx_*; then
    sort -u < data/domains/resolved/short_mx_*
    cut -f1,6 -d' ' < data/domains/resolved/short_mx_* | trim | sort -u |
        while IFS=' ' read -r host mx; do
            echo "${host} ${mx}"
            mkdir -p ../mx/${mx}
            upsert_in_file ../mx/${mx}/hosts ${host}
            nmap_mx ${mx}
        done
fi
