#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

# Assummes nmap in /etc/sudoers, where username is your username
# username ALL = NOPASSWD: /usr/bin/nmap
bingip2host(){
    local ip=${1}
    local file=../ips/${ip}/bing-ip2hosts
    if [[ ! -f ${file} ]]; then
        bash $BING -u -o ${file} ${ip}
        if [[ -s ${file} ]]; then
            notify-send -t 15000 "$(wc -l < ${file}) Bing domains found!" \
                        "$(head ${file})"
        fi
    fi
}

# TODO: use a domain name in the scan and group them
nmap_tcp_fast(){
    local ip=${1}
    local file=../ips/${ip}/tcp
    isvalidxml "${file}.xml" || rm -f ${file}.*
    if [[ ! -f ${file}.nmap ]]; then
        notify-send -t 15000 "TCP Scanning ${ip}..."
        sudo $NMAP \
             -sTV \
             -vv \
             -oA ${file} \
             --max-retries=0 \
             --script-args="http.useragent='${UA}'" \
             --reason \
             -n \
             -F \
             -Pn ${ip}
        if grep /open/ ${file}.gnmap; then
            notify-send -t 15000 "Open ports at ${ip}" \
                        "$(grep -E -o '[0-9]+/open/' ${file}.gnmap)"
        fi
    fi
    add_scan_file ${file}.xml
}

nmap_tcp_full(){
    local ip=${1}
    local file=../ips/${ip}/full_tcp
    isvalidxml "${file}.xml" || rm -f ${file}.*
    add_scan_file ${file}.xml
    if [[ -f ../ips/${ip}/dofull && ! -f ${file}.xml ]]; then
        notify-send -t 15000 "FULL TCP scanning ${ip}..."
        rm -f ../ips/${ip}/dofull
        sudo $NMAP \
             -sT \
             -vv \
             -oA ${file} \
             -T2 \
             --max-retries=0 \
             --reason \
             -n \
             -p- \
             -Pn ${ip}
        if grep /open/ ${file}.gnmap; then
            notify-send -t 15000 "Open ports at ${ip}" \
                        "$(grep -E -o '[0-9]+/open/' ${file}.gnmap)"
        fi
        add_scan_file ${file}.xml
        nmap_tcp_version ${ip}
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

nmap_tcp_version(){
    local ip=${1}
    local file=../ips/${ip}/full_tcp_version
    isvalidxml "${file}.xml" || rm -f ${file}.*
    add_scan_file ${file}.xml
    local ports; ports=$(open_tcp_unknown ${ip} | sort -n | paste -sd,)
    if [[ -n ${ports} ]]; then
        notify-send -t 15000 "Version scan ${ip}..."
        sudo ${NMAP} \
             -sTV \
             --script='default or banner or unusual-port'"$(nmap_ext)" \
             -vv \
             --script-args="http.useragent='${UA}'" \
             -oA ${file} \
             --reason \
             -n \
             -p${ports} \
             -Pn ${ip}
        add_scan_file ${file}.xml
    fi
}

get_ips_up "${DOMAIN}" | rm_local_ips |
    while read -r ip ; do
        nmap_tcp_fast ${ip}
    done

get_ips_up "${DOMAIN}" | rm_local_ips | rm_waf_ips |
    while read -r ip ; do
        bingip2host      ${ip}
        nmap_tcp_full    ${ip}
    done

echo "${0##*/} is DONE!"
