#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}

BING=$HOME/projects/sec/bing-ip2hosts/bing-ip2hosts
NMAP=/usr/local/bin/nmap

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
            notify-send -t 10000 "$(wc -l < ${file}) Bing domains found!" "$(head ${file})"
        fi
    fi
}
nmap_tcp_fast(){
    local ip=${1}
    local file=../ips/${ip}/tcp
    isvalidxml "${file}.xml" ||  rm -f "${file}.xml"
    if [[ ! -f ${file}.nmap ]]; then
        notify-send -t 5000 "TCP Scanning ${ip}..."
        sudo $NMAP \
             -sT \
             -v \
             -oA ${file} \
             --max-retries=0 \
             --reason \
             -n \
             -F \
             -Pn ${ip}
        if grep /open/ ${file}.gnmap; then
            notify-send -t 7000 \
                        "Open ports at ${ip}"\
                        "$(grep -E -o '[0-9]+/open/' ${file}.gnmap)"
        fi
    fi
    add_scan_file ${file}
}
nmap_udp_20(){
    local ip=${1}
    local file=../ips/${ip}/udp
    isvalidxml ${file}.xml || rm -f ${file}.xml
    if [[ ! -f ${file}.xml ]]; then
        notify-send -t 5000 "UDP Scanning ${ip}..."
        sudo $NMAP \
             -sUVC \
             --top-ports=20 \
             -oA ${file} \
             --max-retries=0 \
             --reason \
             -n \
             -F \
             -Pn ${ip}
        if grep /open/ ${file}.gnmap; then
            notify-send -t 7000 \
                        "Open ports at ${ip}" \
                        "$(grep -E -o '[0-9]+/open/' ${file}.gnmap)"
        fi
    fi
    add_scan_file ${file}
}
# nmap_tcp_full(){
#     local ip=${1}
#     local folder=../ips/${ip}
#     if [[ ! -f ${folder}/full_tcp.nmap ]]; then
#         notify-send -t 5000 "FULL TCP scanning ${ip}..."
#         sudo $NMAP -sT -v \
    #              -oA ${folder}/full_tcp --max-retries=0 \
    #              --reason -n -p- -Pn ${ip}
#         if grep /open/ ${folder}/full_tcp.gnmap; then
#             notify-send -t 7000 "Open ports at ${ip}" "$(grep -E -o '[0-9]+/open/' ${folder}/full_tcp.gnmap)"
#         fi
#     fi
#}
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
    add_scan_file ${file}.xml
    local ports; ports=$(open_tcp_unknown ${ip} | sort -n | paste -sd,)
    if [[ -n ${ports} ]]; then
        notify-send -t 10000 "Version scan ${ip}..."
        sudo ${NMAP} \
             -sTV \
             --script='default or banner or unusual-port'"$(nmap_ext)" -v \
             -oA ${file} \
             --reason \
             -n \
             -p${ports} \
             -Pn ${ip}
        add_scan_file ${file}.xml
    fi
}

# get_ips_up_clear "${DOMAIN}" |
#     while read -r ip ; do
#         nmap_tcp_fast ${ip}
#     done

get_ips_up_clear "${DOMAIN}" | rm_waf_ips |
    while read -r ip ; do
        nmap_udp_20  ${ip}
        bingip2host  ${ip}
        #nmap_tcp_full    ${ip}
        #nmap_tcp_version ${ip}
    done

echo "${0##*/} is DONE!"
