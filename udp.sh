#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

nmap_udp_20(){
    local ip=${1}
    local file=../ips/${ip}/udp
    isvalidxml ${file}.xml || rm -f "${file}.*"
    if [[ ! -f ${file}.xml ]]; then
        notify-send -t 15000 "UDP Scanning ${ip}..."
        sudo $NMAP \
             -sUVC \
             -vv \
             --top-ports=20 \
             -oA ${file} \
             --max-retries=0 \
             --reason \
             -n \
             -Pn ${ip}
        if grep /open/ ${file}.gnmap; then
            notify-send -t 15000 "Open ports at ${ip}" \
                        "$(grep -E -o '[0-9]+/open/' ${file}.gnmap)"
        fi
    fi
    add_scan_file ${file}.xml
}

get_ips_up "${DOMAIN}" | rm_local_ips | rm_waf_ips |
    while read -r ip ; do
        nmap_udp_20 ${ip}
    done

