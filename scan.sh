#!/bin/bash

set -exuo pipefail

NMAP_PARSE=$HOME/projects/sec/nmap-parse-output/nmap-parse-output
BING=$HOME/projects/sec/bing-ip2hosts/bing-ip2hosts
NMAP=/usr/bin/nmap

# TODO: reenable tcp scanning on cloud

# https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html
# https://ip-ranges.amazonaws.com/ip-ranges.json

# Assummes this in /etc/sudoers, where username is your username
# username ALL = NOPASSWD: /usr/bin/nmap
trim(){ awk '{$1=$1};1' /dev/stdin; }
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}

bingip2host(){
    local ip=${1}
    local folder=data/${ip}
    if [[ ! -f ${folder}/bing-ip2hosts ]]; then
        bash $BING -u -o ${folder}/bing-ip2hosts ${ip}
        if [[ -s ${folder}/bing-ip2hosts ]]; then
            notify-send -t 10000 "$(wc -l ${folder}/bing-ip2hosts | cut -f1 -d' ') Bing domains found!" "$(cat ${folder}/bing-ip2hosts | head)"
        fi
    fi
}
nmap_tcp_fast(){
    local ip=${1}
    local folder=data/${ip}
    if [[ ! -f ${folder}/tcp.nmap ]]; then
        sudo $NMAP -sT -v \
             -oA ${folder}/tcp --max-retries=0 --reason -n -F -Pn ${ip}
        if grep /open/ ${folder}/tcp.gnmap; then
            notify-send -t 7000 "Open ports at ${ip}" "$(egrep -o '[0-9]+/open/' ${folder}/tcp.gnmap)"
        fi
    fi
}
nmap_udp_20(){
    local ip=${1}
    local folder=data/${ip}
    if [[ ! -f ${folder}/udp.nmap ]]; then
        sudo $NMAP -sUV --packet-trace \
             --top-ports=20 \
             -oA ${folder}/udp --max-retries=0 --reason -n -F -Pn ${ip}
        if grep /open/ ${folder}/udp.gnmap; then
            notify-send -t 7000 "Open ports at ${ip}" "$(egrep -o '[0-9]+/open/' ${folder}/udp.gnmap)"
        fi
    fi
}
nmap_tcp_full(){
    local ip=${1}
    local folder=data/${ip}
    if [[ ! -f ${folder}/full_tcp.nmap ]]; then
        sudo $NMAP -sT -v \
             -oA ${folder}/full_tcp --max-retries=0 --reason -n -p- -Pn ${ip}
        if grep /open/ ${folder}/full_tcp.gnmap; then
            notify-send -t 7000 "Open ports at ${ip}" "$(egrep -o '[0-9]+/open/' ${folder}/full_tcp.gnmap)"
        fi
    fi
}
nmap_tcp_version(){
    local ip=${1}
    local output=data/${ip}/full_tcp_version
    local input=data/${ip}/full_tcp.xml
    local ports="$(bash ${NMAP_PARSE} ${input} ports)"
    if [[ ! -f ${output}.nmap && -f ${input} && -n ${ports} ]]; then
        sudo ${NMAP} -sTVC -v \
             -oA ${output} \
             --reason -n \
             -p${ports} \
             -Pn ${ip}
    fi
}

while read -r ip ; do
    folder=data/${ip}
    mkdir -p "${folder}"
    notify-send -t 5000 "Scanning ${ip}..."
    nmap_udp_20   ${ip}
    nmap_tcp_fast ${ip}
    bingip2host   ${ip}
done < <(fgrep -v -e "CLOUDFRONT" -e "LOCAL" -e "Akamai" -e "AzureFrontDoor.Frontend" -e "Cloudflare" data/up.txt)

if [[ -s data/full.txt ]]; then
    while read -r ip ; do
        folder=data/${ip}
        mkdir -p "${folder}"
        notify-send -t 5000 "FULL Scanning ${ip}..."
        nmap_tcp_full    ${ip}
        nmap_tcp_version ${ip}
    done < <(cat data/full.txt | uncomment | trim)
fi
