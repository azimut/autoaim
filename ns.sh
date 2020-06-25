#!/bin/bash

# TODO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1111

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}
NMAP=/usr/local/bin/nmap

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

FOLDER=domains/ns

mkdir -p ${FOLDER}/../dig
mkdir -p ${FOLDER}/../nmap
mkdir -p ${FOLDER}/../trusttrees

# To any with NS
nmap_nsec(){
    local domain=${1}
    local ns=${2}
    file=${FOLDER}/../nmap/nsec_${domain}_${ns}
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
            file=${FOLDER}/../dig/axfr_${ns}_${ip}_${domain}
            if [[ ! -f ${file} ]]; then
                dig @${ip} ${domain} AXFR 2>&1 | tee ${file}
            fi
        done
}

graph_trusttrees(){
    local domain=${1}
    local filename=${domain}_trust_tree_graph.png
    if [[ ! -f ${FOLDER}/../trusttrees/${domain}_trusttrees.log ]]; then
        cd ${FOLDER}/../trusttrees
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
    file=../ns/${ns}/nmap6
    isvalidxml "${file}.xml" ||  rm -f "${file}.xml"
    if [[ ! -f ${file}.xml ]]; then
        sudo $NMAP -sSUV \
             -PE -PS53 -PU53 \
             -p 53 -n -v \
             --dns-servers 8.8.8.8 \
             -6 \
             --resolve-all \
             --reason \
             --script "banner,dns-nsid,dns-recursion,fcrdns,fingerprint-strings" \
             -oA ${file} \
             ${ns}
    fi
}

# # Work on domains with NS servers
# dns_ns "${DOMAIN}" |
#     while IFS='|' read -r domain ns; do
#         graph_trusttrees ${domain}
#         dig_axfr         ${domain} ${ns}
#         nmap_nsec        ${domain} ${ns}
#     done

dns_ns "${DOMAIN}" |
    while IFS='|' read -r domain ns; do
        mkdir -p ../ns/${ns}/
        upsert_in_file ../ns/${ns}/hosts ${domain}
        fingerprint ${ns}
        add_scan_file ../ns/${ns}/nmap.xml
        add_scan_file ../ns/${ns}/nmap6.xml
        #scavange ${ns} ${domain}
    done

echo "${0##*/} is DONE!"
