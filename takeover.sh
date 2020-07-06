#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}
FOLDER=takeover

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

mkdir -p ${FOLDER}

#go get -u github.com/haccer/subjack

# This takes care of CNAMEs
if [[ $(dns_cname ${DOMAIN} | wc -l) -gt 0 ]]; then
    subjack -ssl -v -w <(dns_cname ${DOMAIN}) 2>&1 | tee ${FOLDER}/output_${DOMAIN}.https.log
    subjack      -v -w <(dns_cname ${DOMAIN}) 2>&1 | tee ${FOLDER}/output_${DOMAIN}.http.log
fi
