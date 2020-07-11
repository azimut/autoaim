#!/bin/bash
# https://github.com/tomnomnom/hacks/tree/master/waybackurls
# https://github.com/tomnomnom/hacks/tree/master/urinteresting
#
# HTTP Proxy:
#   Request:  IP - Port - Host - Path - URL
#   Response: Headers - Code - Content (hash?, content length, js content?)
#   Cache: ?, drop responses we know are 404 OR already done
# DB:
# - ip-port-domain
# - domain-path
# HTTP:
# IP/Port/Domain/path/url/parameters
#        //Service
#               // robots.txt
#               // Cross Domain Policy
#                    //Methods
#                    //Headers
#                          // Length
#                          // Mime Type
#                          // Title
#                          // file by extension
#                          // file backup files

export DOMAIN=${1:-${PWD##*/}}
export FOLDER=http
mkdir -p ${FOLDER}/SubDomainizer
mkdir -p ${FOLDER}/hakrawler
mkdir -p ${FOLDER}/nikto
mkdir -p ${FOLDER}/nmap

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

# if is_port_open 8080 127.0.0.1; then
#     export http_proxy=http://127.0.0.1:8080
#     export https_proxy=http://127.0.0.1:8080
# fi

# To any resolved subdomain
subdomainizer(){
    local domain=${1}
    file=${FOLDER}/SubDomainizer/sub_${domain}.txt
    if [[ ! -f ${file} ]]; then
        #-g -gt $GITHUB_TOKEN # it is buggy
        timeout --signal=9 $((60*2)) \
                python3 ${SUBDOMAINIZER} \
                -k \
                --url ${domain} \
                -o ${file} 2>&1 | tee ${FOLDER}/SubDomainizer/all_${domain}.txt
    fi
}

scan_report "${DOMAIN}" | grep -v 'ssl/[^h]' | cut -f9 -d'|' | sort -u | unwoven -t 25 |
    while read -r url; do
        plugins=(
            auth content_search cookies paths siebel parked  # greps
            msgs outdated                                    # Headers
            put_del_test apache_expect_xss origin_reflection # Exploit
        )
        printf '%s\0%s\0%s\0' "${url}" 'siteall' "$(join_by ';' "${plugins[@]}")"
    done | xargs -0 -n3 -P3 bash -c '{ set -x; niktohost "${@}"; }' --

scan_report "${DOMAIN}" | grep -v 'ssl/[^h]' | cut -f9 -d'|' | sort -u | unwoven -t 25 |
    while read -r url; do
        hakrawlerhost ${url}
    done

scan_report_no_waf "${DOMAIN}" | grep -v 'ssl/[^h]' | cut -f9 -d'|' | sort -u | unwoven -t 25 |
    while read -r url; do
        scripts=(
            "${http_common[@]}"
            "${http_grep[@]}"
            "${http_waf_spider[@]}"
            "${http_waf_site[@]}"
        )
        domain="$(unfurl format '%d' <<< ${url})"
        port="$(get_port "${url}")"
        printf '%s\0%s\0%s\0' "${domain}" "${port}" "$(join_by ',' "${scripts[@]}")"
    done | xargs -0 -n3 -P3 bash -c '{ set -x; nmaprun sitenowaf "${@}"; }' --

# Dodgy add ips data, for http_report
echo "SELECT DISTINCT ON(host) host FROM http_entries" | praw \
    | grepip \
    | rm_ips_with_provider \
    | sunny \
    | add_ip_data
