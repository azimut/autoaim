#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}
NMAP=/usr/local/bin/nmap

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

fingerprint(){
    local ns=${1}
    file=../ns/${ns}/nmap_version
    if [[ ! -f ${file}.gnmap ]]; then
        sudo $NMAP -sSUV \
             -PE -PS53 -PU53 -PP \
             -p 53 -n -v \
             --dns-servers 8.8.8.8 \
             --resolve-all \
             --reason \
             --script "banner,dns-nsid,dns-recursion,fcrdns,fingerprint-strings" \
             -oA ${file} \
             ${ns}
    fi
    # if [[ ! -f ${file}_ip6.gnmap ]]; then
    #     sudo $NMAP -sSUV \
        #          -PE -PS53 -PU53 \
        #          -p 53 -n -v \
        #          --dns-servers 8.8.8.8 \
        #          -6 \
        #          --resolve-all \
        #          --reason \
        #          --script "banner,dns-nsid,dns-recursion,fcrdns,fingerprint-strings" \
        #          -oA ${file}_ip6 \
        #          ${ns}
    # fi
}
dns_ns "${DOMAIN}" |
    while IFS='|' read -r domain ns; do
        mkdir -p ../ns/${ns}/
        upsert_in_file ../ns/${ns}/hosts ${domain}
        fingerprint ${ns}
        #scavange ${ns} ${domain}
    done
