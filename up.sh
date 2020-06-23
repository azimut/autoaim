#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}

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

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

nmap_alive(){
    local ip=${1}
    local filename=../ips/${ip}/alive${DATE}
    mkdir -p ../ips/${ip}
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
        touch ../ips/${ip}/up  ; echo ${ip} | add_ips_up
    else
        touch ../ips/${ip}/down; echo ${ip} | add_ips_down
    fi
}

ips_up()  { find .. -type f -name up   | cut -f3 -d/;}
ips_down(){ find .. -type f -name down | cut -f3 -d/;}

ips_without_provider(){
    uncomment < ips.txt \
        | trim \
        | grep -vxf <(find ../ips/ -type f -name provider | grepip)
}

ips_with_provider(){
    uncomment < ips.txt \
        | trim \
        | grep -xf <(find ../ips/ -type f -name provider | grepip)
}

# If no ips in domain, quit
[[ ! -s  ips.txt ]] && { exit 1; }

ips_up   | add_ips_up
ips_down | add_ips_down

# nmap ping check
get_ips_unknown ${DOMAIN} |
    while read -r ip; do
        nmap_alive ${ip}
    done

# Add PTR
get_ip_noptr ${DOMAIN} |
    while read -r ip; do
        if [[ -s ../ips/${ip}/ptr ]]; then
            cat ../ips/${ip}/ptr
            add_ip_ptr "${ip}" "$(cat ../ips/${ip}/ptr)"
        fi
        if [[ ! -f  ../ips/${ip}/ptr ]]; then
            mkdir -p ../ips/${ip}/
            dig +short @1.1.1.1 -x ${ip} > ../ips/${ip}/ptr
            add_ip_ptr "${ip}" "$(cat ../ips/${ip}/ptr)"
        fi
    done

mapfile -t pending < <(ips_with_provider)
for ip in "${pending[@]}"; do
    echo "${ip},$(cat ../ips/${ip}/cidr),$(cat ../ips/${ip}/provider)" | add_ip_data
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
#     if [[ ! -f ${ip}/bypass ]]; then
#         bash ${BYPASS} 2>&1 | tee ${ip}/bypass
#     fi
# fi
