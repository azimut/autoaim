#!/bin/bash

set -exuo pipefail

mkdir -p data/

#BYPASS=$HOME/projects/sec/bypass-firewalls-by-DNS-history/bypass-firewalls-by-DNS-history.sh
NMAP=/usr/bin/nmap
DATE=$(date +%s)
UA="http.useragent='Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0'"
# hostmap- scripts are broken
SCRIPTS=(
    address-info
    dns-blacklist
    dns-zeustracker
    fcrdns
    traceroute-geolocation
    whois-ip
)
nmap_alive(){
    local ip=${1}
    local filename=../ips/${ip}/alive${DATE}
    sudo $NMAP -n \
         -sn \
         -PE -PS80,443 -PA80 -PP \
         -oA ${filename} \
         --script-args="${UA},traceroute-geolocation.kmlfile='../ips/${ip}/map'" \
         --traceroute \
         --script "$(printf '%s,' "${SCRIPTS[@]}")" \
         --reason -v \
         ${ip}
    if grep Up ${filename}.gnmap; then
        touch ../ips/${ip}/up
    else
        touch ../ips/${ip}/down
    fi
}
trim(){ awk '{$1=$1};1' /dev/stdin; }
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}
grepip(){
    grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" /dev/stdin
}
ips_without_provider(){
    uncomment < data/ips.txt \
        | trim \
        | grep -vxf <(find ../ips/ -type f -name provider | grepip)
}
upsert_in_file(){
    local file="${1}"
    shift
    local inserts=("${@}")
    [[ ! -f ${file} ]] && return 1
    for insert in "${inserts[@]}" ; do
        grep -F -x "${insert}" "${file}" \
            || echo "${insert}" >> "${file}"
    done
}

# If no ips in domain, quit
[[ ! -s  data/ips.txt ]] && { exit 1; }

# Add domain into ips list
uncomment < data/ips.txt | trim |
    while read -r ip; do
        domain=${PWD%/}
        domain=${domain##*/}
        mkdir -p ../ips/${ip}/
        touch ../ips/${ip}/domains
        upsert_in_file ../ips/${ip}/domains ${domain}
    done

# nmap ping check
uncomment < data/ips.txt | trim |
    while read -r ip; do
        if [[ ! -f ../ips/${ip}/up && ! -f ../ips/${ip}/down ]]; then
            nmap_alive ${ip}
        fi
    done

# Add PTR
uncomment < data/ips.txt | trim |
    while read -r ip; do
        if [[ ! -f ../ips/${ip}/ptr ]]; then
            dig +short @1.1.1.1 -x ${ip} > ../ips/${ip}/ptr
        fi
    done

# Add Provider - Ignore ips already processed
mapfile -t pending < <(ips_without_provider)
if [[ ${#pending[@]} -ne 0 ]]; then
    printf "%s\n" "${pending[@]}" | sunny |
        while IFS=, read -r ip cidr provider; do
            cidr=${cidr// }
            provider=${provider// }
            provider=${provider//\"}
            echo ${cidr}     > ../ips/${ip}/cidr
            echo ${provider} > ../ips/${ip}/provider
        done
fi
## TODO: I can't do this properly without follow CNAME's resolved, I mean...I want to target
##       only domains behind a cloud provider...a way could it be provide more ips to bypass
# Bypass
# if [[ ${provider} == "CLOUDFRONT" || ${provider} == "Akamai" || ${provider} == "AzureFrontDoor.Frontend" || ${provider} == "Cloudflare" ]]; then
#     if [[ ! -f data/${ip}/bypass ]]; then
#         bash ${BYPASS} 2>&1 | tee data/${ip}/bypass
#     fi
# fi
