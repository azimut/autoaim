#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

FOLDER=domains

mkdir -p ${FOLDER}/dig
mkdir -p ${FOLDER}/nmap
mkdir -p ${FOLDER}/trusttrees

# To any with NS
nmap_nsec(){
    local domain=${1}
    local ns=${2}
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

# To any with NS/sub, assume NS resolves
dig_axfr(){
    local domain=${1}
    local ns=${2}
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

fingerprint(){
    local ns=${1}
    local file=""
    file=../ns/${ns}/nmap
    isvalidxml "${file}.xml" ||  rm -f "${file}.xml"
    if [[ ! -f ${file}.xml ]]; then
        sudo $NMAP -sTUV \
             -PE -PS53 -PU53 -PP \
             --top-ports=1000 \
             -p 'U:53,T:*' \
             -n -vv \
             --dns-servers 8.8.8.8 \
             --resolve-all \
             --reason \
             --script "banner,dns-nsid,dns-recursion,fcrdns,fingerprint-strings" \
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
             --resolve-all \
             --reason \
             --script "banner,dns-nsid,dns-recursion,fcrdns,fingerprint-strings" \
             -oA ${file} \
             ${ns}
    fi
    add_scan_file ${file}
}

# basic scan ONLY to ones that are worth
dns_ns "${DOMAIN}" | grep -F -v -e awsdns -e cscdns | cut -f2 -d'|' | sort -u |
    while read -r ns; do
        mkdir -p ../ns/${ns}/
        fingerprint ${ns}
    done

# NS-DOMAIN joined queries
dns_ns "${DOMAIN}" |
    while IFS='|' read -r domain ns; do
        graph_trusttrees ${domain}
        dig_axfr         ${domain} ${ns}
        nmap_nsec        ${domain} ${ns}
    done

# query ALL, fordns records
for qtype in 'A' 'AAAA'; do
    dns_ns "${DOMAIN}" | cut -f2 -d'|' | sort -u | massdns_inline ${qtype} | add_other ${qtype}
done

echo "${0##*/} is DONE!"
