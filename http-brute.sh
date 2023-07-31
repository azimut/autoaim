#!/bin/bash

export DOMAIN=${1:-${PWD##*/}}
export FOLDER=http
mkdir -p ${FOLDER}/SubDomainizer
mkdir -p ${FOLDER}/hakrawler
mkdir -p ${FOLDER}/nikto
mkdir -p ${FOLDER}/nmap

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

# TODO: change tunning

# Note: works with ip=vhost too.
# -Display V
# local plugins=(sitefiles tests report_text)
niktoweb(){
    local host="${1}"
    local plugins=(sitefiles tests dictionary domino embedded report_text shellshock multiple_index)
    local ssl; [[ ${host} == https* ]] && ssl='-ssl' || ssl='-nossl'
    local domain;domain="$(unfurl format '%d' <<< "${host}")"
    local file=${FOLDER}/nikto/run_${domain}_aggresive.log
    if [[ ! -f ${file} ]] ; then
        proxychains $NIKTO -Plugins "$(join_by ';' "${plugins[@]}")" \
                    -ask no -nointeractive \
                    -useragent "${UA}" \
                    -F txt -output ${file} \
                    -Cgidirs all \
                    -Tuning x123456789abcde \
                    ${ssl} -host "${host}"
    fi
}

# scan_report_no_waf "${DOMAIN}" | grep -v 'ssl/[^h]' | cut -f9 -d'|' | sort -u | unwoven -t 25 |
#     while read -r url; do
#         printf '%s\0' "${url}"
#     done | xargs -0 -n3 -P3 bash -c '{ set -x; niktoweb "${@}"; }' --

scan_report_no_waf "${DOMAIN}" | grep -v 'ssl/[^h]' | cut -f9 -d'|' | sort -u | unwoven -t 25 |
    while read -r url; do
        scripts=(
            "${http_grep[@]}"
            "${http_common[@]}"
            "${http_get_site[@]}"
            "${http_nowaf_site[@]}"
            #"${http_nowaf_spider[@]}"
        )
        domain="$(unfurl format '%d' <<< ${url})"
        port="$(get_port "${url}")"
        printf '%s\0%s\0%s\0' "${domain}" "${port}" "$(join_by ',' "${scripts[@]}")"
    done | xargs -0 -n3 -P2 bash -c '{ set -x; nmapruntor aggressive "${@}"; }' --
