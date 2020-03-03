#!/bin/bash

set -exuo pipefail

MASSDNS=$HOME/projects/sec/massdns/bin/massdns
RESOLVERS=$HOME/projects/sec/autoaim/resolvers.txt
CONCURRENCY=20

trim(){ awk '{$1=$1};1' /dev/stdin; }
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}
revip() {
    awk -F. '{print $4"."$3"." $2"."$1}' /dev/stdin
}
toptr(){
    revip < /dev/stdin | sed 's/$/.in-addr.arpa./g'
}
expandcidr(){
    local cidr=${1}
    nmap -sL -sn -n "${cidr}" | grep report | cut -f5 -d' '
}

mkdir -p data/cidrptr

# -r single resolver due >>>>>>><
# https://github.com/OWASP/Amass/issues/349
grep '/' data/ips.txt | uncomment | trim |
    while read -r cidr; do
        filename=${cidr/\//N}
        file=data/cidrptr/${filename}
        if [[ ! -f ${file} ]]; then
            $MASSDNS \
                -s ${CONCURRENCY} \
                --retry SERVFAIL \
                -c 25 \
                -o S \
                -t PTR \
                -r "${RESOLVERS}" \
                -w "${file}" \
                <(expandcidr "${cidr}" | revip | sed 's/$/.in-addr.arpa/g')
        fi
    done
