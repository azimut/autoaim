#!/bin/bash

# NOTE: assuming that you trust the DNS servers you just want to know if they reply a request for domain

set -eu

[[ -s $1 ]] || { echo "Invalid INPUT_FILE"; exit 1; }

INPUT_FILE=${1}
DOMAIN=${2}
JOBS=${3:-20}
OUTPUT_FILE=${4:-$INPUT_FILE}

RANDOM_SUBDOMAIN="$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 16 | head -n1)"
TMPFILE=raw_${DOMAIN}_${RANDOM}_resolvers.txt

doit()
{
    local resolverip="$1"
    local domain="$2"
    local random_subdomain="$3"
    local s=()
    # know A
    if s=($(dig @${resolverip} +short +timeout=1 "${domain}" "${random_subdomain}.${domain}")); then
        if [[ ${#s[@]} -eq 0 ]]; then
            echo "DOWN ${resolverip} EMPTY_A"
            return 1
        elif [[ ${#s[@]} -eq 2 ]]; then
            echo "DOWN ${resolverip} BOGUS_WILDCARD"
            return 1
        fi
    else
        echo "DOWN ${resolverip} TIMEOUT_A"
        return 1
    fi
    echo "UP ${resolverip}"
}
export -f doit

mapfile -t ips < <(cat "${INPUT_FILE}" | xargs | tr ' ' $'\n')
parallel -j"${JOBS}" doit ::: "${ips[@]}" ::: ${DOMAIN} ::: ${RANDOM_SUBDOMAIN} \
    | tee ${TMPFILE}
grep UP ${TMPFILE} \
    | cut -f2 -d' ' \
    | sort | uniq | sort -V > ${OUTPUT_FILE}
