#!/bin/bash

DOMAIN=${1:-${PWD##*/}}

FOLDER=domains/resolved
SUBDOMAINIZER=$HOME/projects/sec/SubDomainizer/SubDomainizer.py

mkdir -p ${FOLDER}/../SubDomainizer
mkdir -p ${FOLDER}/../hakrawler

# To any resolved subdomain
subdomainizer(){
    local domain=${1}
    file=${FOLDER}/../SubDomainizer/sub_${domain}.txt
    if [[ ! -f ${file} ]]; then
        #-g -gt $GITHUB_TOKEN # it is buggy
        timeout --signal=9 120 python3 ${SUBDOMAINIZER} \
                -k \
                --url ${domain} \
                -o ${file} 2>&1 | tee ${FOLDER}/../SubDomainizer/all_${domain}.txt
    fi
}

# To any resolved subdomain
hakrawler(){
    local domain=${1}
    local port=${2-80}
    if [[ ${port} -eq 80 ]]; then
        local url=http://${domain}/
    else
        local url=https://${domain}/
    fi
    local file=${FOLDER}/../hakrawler/out_${domain}_${port}.txt
    if [[ ! -f ${file} ]]; then
        timeout 120 hakrawler \
                -scope yolo \
                -linkfinder -depth 3 \
                -url ${url} 2>&1 | tee ${file}
    fi
}

# # TODO: do port 443
# # Work on resolved domains
# for domain in "${domains[@]}"; do
#     if is_port_open 80 ${domain}; then
#         hakrawler     ${domain}
#         subdomainizer ${domain}
#     fi
# done
