#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}

FOLDER=http/aquatone
mkdir -p ${FOLDER}/ips
mkdir -p ${FOLDER}/domains

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

# TODO: doesn't check if a new port was opened
aquatone_processed_ips(){
    local file=${FOLDER}/ips/aquatone_urls.txt
    [[ -f ${file} ]] && cut -f3 -d/ ${file} | sort -Vu
}
aquatone_processed_urls(){
    local file=${FOLDER}/domains/aquatone_urls.txt
    [[ -f ${file} ]] && sort -u < ${file}
}

ports="$(scan_report ${DOMAIN} | grep -F http | grep -v 'ssl/[^h]' | cut -f5 -d'|' | sort -nu | paste -sd,)"

# IPs, ignore waf ips
mapfile -t pending < <(complement <(aquatone_processed_ips) \
                                  <(scan_report ${DOMAIN} | grep -F http | grep -v 'ssl/[^h]' | cut -f2 -d'|' | sort -Vu | rm_local_ips | rm_waf_ips))
if [[ ${#pending[@]} -gt 0 ]]; then
    echo "Processing ${#pending[@]} ips..."
    notify-send -t 15000 "Aquatone" "Processing ${#pending[@]} ips on ports ${ports}"
    rm -rf ${FOLDER}/ips
    printf '%s\n' "${pending[@]}" | \
        $AQUATONE -screenshot-timeout 60000 \
                  -scan-timeout 1000 \
                  -debug \
                  -ports "${ports}" \
                  -threads 1 \
                  -out ${FOLDER}/ips 2>&1 | tee ${FOLDER}/ips/output.log
fi

# Domains
mapfile -t pending < <(complement <(aquatone_processed_urls) \
                                  <(scan_report ${DOMAIN} | grep -F http | grep -v 'ssl/[^h]' | cut -f9 -d'|' | sort -u))
if [[ ${#pending[@]} -gt 0 ]]; then
    echo "Processing ${#pending[@]} domains..."
    notify-send -t 15000 "Aquatone" "Processing ${#pending[@]} ips on ports ${ports}"
    rm -rf ${FOLDER}/domains
    printf '%s\n' "${pending[@]}" | \
        $AQUATONE -screenshot-timeout 60000 \
                  -scan-timeout 1000 \
                  -debug \
                  -ports "${ports}" \
                  -threads 1 \
                  -out ${FOLDER}/domains | tee ${FOLDER}/domains/output.log
fi
