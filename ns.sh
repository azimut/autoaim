#!/bin/bash

set -exuo pipefail

NMAP=/usr/local/bin/nmap

upsert_in_file(){
    local file="${1}"
    shift
    local inserts=("${@}")
    if [[ ! -f ${file} ]]; then
        touch ${file}
    fi
    for insert in "${inserts[@]}" ; do
        grep -F -x "${insert}" "${file}" \
            || echo "${insert}" >> "${file}"
    done
}
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}
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

if compgen -G data/domains/resolved/ns_*gz; then
    zgrep -h 'IN NS ' data/domains/resolved/ns_*gz | cut -f1,5 -d' ' | sort -u |
        while read -r domain ns; do
            mkdir -p ../ns/${ns}/
            upsert_in_file ../ns/${ns}/hosts ${domain}
            fingerprint ${ns}
            #scavange ${ns} ${domain}
        done
fi
