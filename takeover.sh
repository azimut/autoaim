#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}
FOLDER=data/takeover

mkdir -p ${FOLDER}

cnamedomains(){
    local domain=${1}
    grep CNAME data/domains/resolved/short_a_${domain}.txt \
        | cut -f1 -d' ' \
        | sort | uniq \
        | rev | cut -c2- | rev \
        | grep ${domain}
}

# This takes care of CNAMEs
if cnamedomains ${DOMAIN} &>/dev/null; then
    subjack -ssl -m -v -w <(cnamedomains ${DOMAIN}) 2>&1 \
        | tee ${FOLDER}/output_${DOMAIN}.https.log
    subjack -m -v -w <(cnamedomains ${DOMAIN}) 2>&1 \
        | tee ${FOLDER}/output_${DOMAIN}.http.log
fi
