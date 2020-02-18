#!/bin/bash

set -euo pipefail

DOMAIN=${1:-${PWD##*/}}
FOLDER=data/second-takeover

CONCURRENCY=${2:-20}
RESOLVERS=$HOME/projects/sec/autoaim/resolvers.txt
MASSDNS=$HOME/projects/sec/massdns/bin/massdns

mkdir -p ${FOLDER}

grinch(){
    sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" /dev/stdin
}
lowercase(){
    tr '[:upper:]' '[:lower:]' < /dev/stdin
}
unresolved_domains() {
    local domain=${1}
    local filename=a_${domain}.txt.gz
    local filepath=${FOLDER}/${filename}
    if [[ -f ${filepath} ]]; then
        zgrep -A7 NXDOMAIN ${filepath} \
            | grep 'IN A$' \
            | cut -f1 -d' ' \
            | sort \
            | uniq
    fi
}
# Depends on hakrawler
inlinedomains(){
    grep -h subdomain ./data/domains/hakrawler/*.txt \
        | grinch \
        | sort -u \
        | cut -f2 -d' ' \
        | lowercase
}
massdns(){
    local type=${1}
    shift
    local domains=("${@}")
    local output=${FOLDER}/${type,,}_${DOMAIN}.txt
    $MASSDNS \
        -s ${CONCURRENCY} \
        --retry SERVFAIL \
        -c 25 \
        -o F \
        -t ${type} \
        -r ${RESOLVERS} \
        -w ${output} \
        <(printf '%s\n' "${domains[@]}" | sort | uniq)
    if [[ ${type} == 'A' ]]; then
        if grep -q -e "IN ${type} " -e 'IN CNAME ' ${output}; then
            grep -e "IN ${type} " -e 'IN CNAME ' ${output} \
                 > ${FOLDER}/short_${type,,}_${DOMAIN}.txt
        fi
    else
        if grep -q "IN ${type} " ${output}; then
            grep "IN ${type} " ${output} \
                 > ${FOLDER}/short_${type,,}_${DOMAIN}.txt
        fi
    fi
    gzip --best -f ${output}
}

mapfile -t domains < <(inlinedomains)

if [[ ${#domains[@]} -gt 0 ]]; then
    massdns A "${domains[@]}"
    mapfile -t unresolved < <(unresolved_domains ${DOMAIN})
    echo "${#unresolved[@]} domains..."
    if inlinedomains &>/dev/null; then
        subjack -ssl -m -v -w <(inlinedomains) 2>&1 \
            | tee ${FOLDER}/subjack_${DOMAIN}.https.log
        subjack -m -v -w <(inlinedomains) 2>&1 \
            | tee ${FOLDER}/subjack_${DOMAIN}.http.log
    fi
    grep -v 'Not Vulnerable' ${FOLDER}/subjack* || true
fi
