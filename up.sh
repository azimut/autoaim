#!/bin/bash

set -exuo pipefail

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
        | grep -vxf <(find data/ -name provider | grepip)
}
#BYPASS=$HOME/projects/sec/bypass-firewalls-by-DNS-history/bypass-firewalls-by-DNS-history.sh
NMAP=/usr/bin/nmap
DATE=$(date +%s)
UA="http.useragent='Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0'"
# hostmap- scripts are broken
SCRIPTS=(
    asn-query
    address-info
    dns-blacklist
    dns-zeustracker
    fcrdns
    traceroute-geolocation
    whois-ip
)

mkdir -p data/

if compgen -G 'data/alive*.gnmap'; then
    grep Up   data/alive*.gnmap | cut -f2 -d' ' | sort | uniq | sort -V > data/up.txt   || true
    grep Down data/alive*.gnmap | cut -f2 -d' ' | sort | uniq | sort -V > data/down.txt || true
    cat data/up.txt data/down.txt | sort | uniq | sort -V > data/processed.txt
else
    touch data/processed.txt
fi

# Note: Plus -PS80 from default
sudo $NMAP -n \
     -sn \
     -PE -PS80,443 -PA80 -PP \
     -oA data/alive${DATE} \
     --script-args="${UA}" \
     --traceroute \
     --script "$(printf '%s,' "${SCRIPTS[@]}")" \
     --reason -v \
     --excludefile data/processed.txt \
     --randomize-hosts \
     -iL data/ips.txt

grep Up   data/alive*.gnmap | cut -f2 -d' ' | sort | uniq | sort -V > data/up.txt   || true
grep Down data/alive*.gnmap | cut -f2 -d' ' | sort | uniq | sort -V > data/down.txt || true
cat data/up.txt data/down.txt | sort | uniq | sort -V > data/processed.txt

# Add Provider - Ignore ips already processed
mapfile -t pending < <(ips_without_provider)

if [[ ${#pending[@]} -ne 0 ]]; then
    printf "%s\n" "${pending[@]}" | sunny |
        while IFS=, read -r ip cidr provider; do
            mkdir -p data/${ip}
            cidr=${cidr// }
            provider=${provider// }
            provider=${provider//\"}
            echo ${cidr}     > data/${ip}/cidr
            echo ${provider} > data/${ip}/provider
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

# Add PTR
uncomment < data/ips.txt | trim |
    while read -r ip; do
        mkdir -p data/${ip}
        if [[ ! -f data/${ip}/ptr ]]; then
            dig +short @1.1.1.1 -x ${ip} > data/${ip}/ptr
        fi
    done
