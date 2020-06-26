#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}

NMAP_PARSE=$HOME/projects/sec/nmap-parse-output/nmap-parse-output
BING=$HOME/projects/sec/bing-ip2hosts/bing-ip2hosts
NMAP=/usr/local/bin/nmap

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

# Assummes nmap in /etc/sudoers, where username is your username
# username ALL = NOPASSWD: /usr/bin/nmap
bingip2host(){
    local ip=${1}
    local folder=../ips/${ip}
    if [[ ! -f ${folder}/bing-ip2hosts ]]; then
        bash $BING -u -o ${folder}/bing-ip2hosts ${ip}
        if [[ -s ${folder}/bing-ip2hosts ]]; then
            notify-send -t 10000 "$(wc -l < ${folder}/bing-ip2hosts) Bing domains found!" "$(head ${folder}/bing-ip2hosts)"
        fi
    fi
}

nmap_tcp_fast(){
    local ip=${1}
    local file=../ips/${ip}/tcp
    isvalidxml "${file}.xml" ||  rm -f "${file}.xml"
    if [[ ! -f ${file}.nmap ]]; then
        notify-send -t 5000 "Scanning ${ip}..."
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
}
nmap_udp_20(){
    local ip=${1}
    local file=../ips/${ip}/udp
    isvalidxml "${file}.xml" ||  rm -f "${file}.xml"
    if [[ ! -f ${file}.nmap ]]; then
        notify-send -t 5000 "Scanning ${ip}..."
        sudo $NMAP \
             -sUVC \
             --packet-trace \
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
}
# nmap_ext(){
#     local nmap_ext=( ssh ssl smtp pop3 tls imap )
#     local nmap_string=""
#     for proto in "${nmap_ext[@]}"; do
#         nmap_string+=" or (*${proto}* and (discovery or safe or auth))"
#     done
#     echo "${nmap_string}"
# }
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
# nmap_tcp_version(){
#     local ip=${1}
#     local output=../ips/${ip}/full_tcp_version
#     local input=../ips/${ip}/full_tcp.xml
#     if [[ ! -f ${input} ]]; then
#         return 1
#     fi
#     local ports; ports="$(bash ${NMAP_PARSE} ${input} ports)"
#     if [[ ! -f ${output}.nmap && -n ${ports} ]]; then
#         notify-send -t 10000 "FULL Version ${ip}..."
#         sudo ${NMAP} -sTV --script='default or banner or unusual-port'"$(nmap_ext)" -v \
    #              -oA ${output} \
    #              --reason -n \
    #              -p${ports} \
    #              -Pn ${ip}
#     fi
# }

get_ips_up_clear "${DOMAIN}" |
    while read -r ip ; do
        if [[ -f ../ips/${ip}/up ]]; then
            nmap_udp_20   ${ip}
            add_scan_file ../ips/${ip}/udp.xml
            nmap_tcp_fast ${ip}
            add_scan_file ../ips/${ip}/tcp.xml
            #bingip2host   ${ip}
        fi
    done
# while read -r ip ; do
#     if [[ -f ../ips/${ip}/full ]]; then
#         nmap_tcp_full    ${ip}
#         nmap_tcp_version ${ip}
#     fi
# done < ips.txt

echo "${0##*/} is DONE!"
