#!/bin/bash

set -e
set -x

BING=$HOME/projects/sec/bing-ip2hosts/bing-ip2hosts
NMAP=/usr/bin/nmap

# Assummes this in /etc/sudoers, where username is your username
# username ALL = NOPASSWD: /usr/bin/nmap

while read -r ip ; do
    folder=data/"${ip/\//N}"
    mkdir -p "${folder}"
    notify-send "Scanning ${ip}..."
    # UDP
    if [[ ! -f ${folder}/udp.nmap ]]; then
        sudo $NMAP -sUV --packet-trace \
             -oA ${folder}/udp --max-retries=0 --reason -n -F -Pn ${ip}
        grep /open/ ${folder}/udp.gnmap &&
            notify-send $(echo -e "At ${ip}\n$(egrep -o '[0-9]+/open/' ${folder}/udp.gnmap)")
    fi
    # TCP
    if [[ ! -f ${folder}/tcp.nmap ]]; then
        sudo $NMAP -sT -v \
             -oA ${folder}/tcp --max-retries=0 --reason -n -F -Pn ${ip}
        grep /open/ ${folder}/tcp.gnmap &&
            notify-send $(echo -e "At ${ip}\n$(egrep -o '[0-9]+/open/' ${folder}/tcp.gnmap)")
    fi
    # BING-IP2HOST
    if [[ ! -f ${folder}/bing-ip2hosts ]]; then
        bash $BING -u -o ${folder}/bing-ip2hosts ${ip}
        [[ -s ${folder}/bing-ip2hosts ]] &&
            notify-send $(cat ${folder}/bing-ip2hosts)
    fi
done < data/up.txt
