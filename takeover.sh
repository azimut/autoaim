#!/bin/bash

set -exuo pipefail

FOLDER=takeover

[[ -f ./env.sh ]] && source ./env.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

mkdir -p ${FOLDER}

#go get -u github.com/haccer/subjack

mapfile -t domains < <(echo "SELECT DISTINCT ON (data) data
                             FROM dns_record
                             WHERE rtype='CNAME'
                             AND qtype='A'"\
                                 | praw)

# This takes care of CNAMEs
if [[ ${#domains[@]} -gt 0 ]]; then
    subjack -ssl -v -w <(printf '%s\n' "${domains[@]}") 2>&1 | tee ${FOLDER}/output_${DOMAIN}.https.log
    subjack      -v -w <(printf '%s\n' "${domains[@]}") 2>&1 | tee ${FOLDER}/output_${DOMAIN}.http.log
fi
