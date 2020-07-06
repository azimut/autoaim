#!/bin/bash

set -exu

DOMAIN=${1:-${PWD##*/}}

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

FOLDER=ns
mkdir -p ${FOLDER}/dig
mkdir -p ${FOLDER}/nmap
mkdir -p ${FOLDER}/trusttrees

# To any with NS
nmap_nsec(){
    local domain=${1} ns=${2}
    file=${FOLDER}/nmap/nsec_${domain}_${ns}
    if [[ ! -f ${file}.gnmap ]]; then
        sudo $NMAP -sn -n -v -Pn \
             --reason \
             --dns-servers 1.1.1.1 \
             --script "dns-nsec-enum,dns-nsec3-enum" \
             --script-args "dns-nsec-enum.domains=${domain},dns-nsec3-enum.domains=${domain}" \
             -oA ${file} \
             ${ns}
    fi
}

# To any with NS
dig_any(){
    local domain=${1} ns=${2}
    dig @1.1.1.1 +short ${ns} A | trim |
        while read -r ip; do
            file=${FOLDER}/dig/any_${ns}_${ip}_${domain}
            if [[ ! -f ${file} ]]; then
                dig @${ip} ${domain} ANY 2>&1 | tee ${file}
            fi
        done
}

# To any with NS/sub
dig_axfr(){
    local domain=${1} ns=${2}
    dig @1.1.1.1 +short ${ns} A | trim |
        while read -r ip; do
            file=${FOLDER}/dig/axfr_${ns}_${ip}_${domain}
            if [[ ! -f ${file} ]]; then
                dig @${ip} ${domain} AXFR 2>&1 | tee ${file}
            fi
        done
}

graph_trusttrees(){
    local domain=${1}
    local filename=${domain}_trust_tree_graph.png
    if [[ ! -f ${FOLDER}/trusttrees/${domain}_trusttrees.log ]]; then
        cd ${FOLDER}/trusttrees
        trusttrees --gandi-api-v5-key $GANDI_API \
                   --resolvers <(echo -e "8.8.8.8\n1.1.1.1") \
                   --target ${domain} -x png 2>&1 | tee ${domain}_trusttrees.log
        mv output/${filename} .
        rm -rf ./output
        cd -
    fi
}

nmap_ext(){
    local nmap_ext=( ssh ssl smtp pop3 tls imap )
    local nmap_string=""
    for proto in "${nmap_ext[@]}"; do
        nmap_string+=" or (*${proto}* and (discovery or safe or auth))"
    done
    echo "${nmap_string}"
}

fingerprint(){
    local ns=${1}
    local file=""
    mkdir -p ../ns/${ns}/
    file=../ns/${ns}/nmap
    isvalidxml "${file}.xml" ||  rm -f "${file}.xml"
    if [[ ! -f ${file}.xml ]]; then
        sudo $NMAP -sTUV \
             -PE -PS53 -PU53 -PP \
             --top-ports=1000 \
             -p 'U:53,T:*' \
             -n -vv \
             --dns-servers 8.8.8.8 \
             --script-args="http.useragent='${UA}'" \
             --resolve-all \
             --reason \
             --script "banner or dns-nsid or dns-recursion or fcrdns or fingerprint-strings $(nmap_ext)" \
             -oA ${file} \
             ${ns}
    fi
    add_scan_file ${file}
    file=../ns/${ns}/nmap6
    isvalidxml "${file}.xml" ||  rm -f "${file}.xml"
    if [[ ! -f ${file}.xml ]]; then
        sudo $NMAP -sTUV \
             -PE -PS53 -PU53 \
             --top-ports=1000 \
             -p 'U:53,T:*' \
             -n -vv \
             --dns-servers 8.8.8.8 \
             -6 \
             --script-args="http.useragent='${UA}'" \
             --resolve-all \
             --reason \
             --script "banner or dns-nsid or dns-recursion or fcrdns or fingerprint-strings $(nmap_ext)" \
             -oA ${file} \
             ${ns}
    fi
    add_scan_file ${file}
}

# query ALL, fordns records
for qtype in 'A' 'AAAA'; do
    dns_ns "${DOMAIN}" | cut -f2 -d'|' | sort -u | massdns_inline ${qtype} | add_other ${qtype}
done

# basic scan ONLY to ones that are worth
dns_ns "${DOMAIN}" | cut -f2 -d'|' | sort -u | grep -F -v -e '.awsdns-' -e cscdns -e '.akam.net' -e 'mailgun.org' |
    while read -r ns; do
        fingerprint ${ns}
    done

# NS-DOMAIN joined queries, on all as they might be mis-configured...i think
dns_ns "${DOMAIN}" |
    while IFS='|' read -r domain ns; do
        graph_trusttrees ${domain}
        dig_axfr         ${domain} ${ns}
        dig_any          ${domain} ${ns}
        nmap_nsec        ${domain} ${ns}
    done

echo "${0##*/} is DONE!"
