#!/bin/bash

set -exuo pipefail

trim(){ awk '{$1=$1};1' /dev/stdin; }
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}

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
     --script $(printf '%s,' ${SCRIPTS[@]}) \
     --reason -v \
     --excludefile data/processed.txt \
     --randomize-hosts \
     -iL data/ips.txt

grep Up   data/alive*.gnmap | cut -f2 -d' ' | sort | uniq | sort -V > data/up.txt   || true
grep Down data/alive*.gnmap | cut -f2 -d' ' | sort | uniq | sort -V > data/down.txt || true
cat data/up.txt data/down.txt | sort | uniq | sort -V > data/processed.txt

# Add Provider
cat data/ips.txt | uncomment | trim | sunny | \
    while IFS=, read -r ip cidr provider; do
        mkdir -p data/${ip}
        echo ${cidr}     > data/${ip}/cidr
        echo ${provider} > data/${ip}/provider
    done

# Add PTR
cat data/ips.txt | uncomment | trim | \
    while read -r ip; do
        mkdir -p data/${ip}
        if [[ ! -f data/${ip}/ptr ]]; then
            dig +short @1.1.1.1 -x ${ip} > data/${ip}/ptr
        fi
    done
