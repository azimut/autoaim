#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}

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
    local file
    file=../mx/${mx}/nmap6
    isvalidxml "${file}.xml" ||  rm -f "${file}.xml"
    if [[ ! -f ${file}.xml ]]; then
        sudo $NMAP -n \
             -PE -PS25,465 -PA25 \
             -vv -sTV --reason \
             -oA ${file} \
             -F \
             -6 \
             --resolve-all \
             --script='default or banner or fcrdns'"$(nmap_ext)" \
             ${mx}
    fi
    add_scan_file ${file}
    file=../mx/${mx}/nmap
    isvalidxml "${file}.xml" ||  rm -f "${file}.xml"
    if [[ ! -f ${file}.xml ]]; then
        sudo $NMAP -n \
             -PE -PS25,465 -PA25 -PP \
             -vv -sTV --reason \
             -oA ${file} \
             -F \
             --resolve-all \
             --script='default or banner or fcrdns'"$(nmap_ext)" \
             ${mx}
    fi
    add_scan_file ${file}
}

dns_mx "${DOMAIN}" |
    while IFS='|' read -r _ mx; do
        mkdir -p ../mx/${mx}
        nmap_mx ${mx}
    done

for qtype in 'A' 'AAAA'; do
    dns_mx "${DOMAIN}" | cut -f2 -d'|' | sort -u | massdns_inline ${qtype} | add_other ${qtype}
done

echo "${0##*/} is DONE!"
