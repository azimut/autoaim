#!/bin/bash

# Can't be nopipefail due parallel returning in the return code the number of failed jobs
set -exu

INPUT_FILE=${1}
JOBS=${2:-20}
OUTPUT_FILE=${3:-$INPUT_FILE}

BASE_DOMAINS=(telegram.com starbucks.com.ar) # sites that return the same IP regardless the location, some dns servers might even not be able to reply for a specific TLD
BASE_DOMAIN=${4:-${BASE_DOMAINS[$((RANDOM%${#BASE_DOMAINS[@]}))]}}
BASE_RESOLVERS=(1.1.1.1 8.8.8.8 9.9.9.9)
BASE_RESOLVER=${BASE_RESOLVERS[$((RANDOM%${#BASE_RESOLVERS[@]}))]}

STATIC_IP="$(dig +short @${BASE_RESOLVER} ${BASE_DOMAIN})"
RANDOM_SUB="$(openssl rand -base64 32 | tr -dc 'a-z0-9' | fold -w16 | head -n1)"

TMPFILE=raw_${RANDOM}_resolvers.txt

usage(){
    echo "> ./$0 <INPUT_FILE> [CONCURRENCY] [OUTPUT_FILE]"
    echo "INPUT_FILE  plain text with ip adresses of DNS resolvers"
    echo "CONCURRENCY number of threads to run default is ${JOBS}"
    echo "OUTPUT_FILE file where to put the output validated servers default is INPUT_FILE"
}

[[ -s $INPUT_FILE ]] || { echo "Invalid INPUT_FILE"; usage; exit 1; }

doit(){
    local resolverip="${1}"
    local domain="${2}"
    local ip="${3}"
    local random_sub="${4}"
    local s=""
    local a=()
    local sketchy=(facebook.com paypal.com google.com telegram.com wikileaks.com)
    # know A
    if s=$(dig @${resolverip} +short +timeout=2 ${domain}); then
        if [[ ${s} != "${ip}" ]]; then
            echo "DOWN ${resolverip} BOGUS_A \"${s}\" ${domain} ${ip}"
            return 1
        fi
    else
        echo "DOWN ${resolverip} TIMEOUT_A"
        return 1
    fi
    # SOA and PTR
    if IFS=$'\n' a=($(dig @${resolverip} +short +timeout=5 google.com SOA 8.8.8.8.in-addr.arpa PTR)); then
        if [[ ${#a[@]} -eq 0 ]]; then
            echo "DOWN ${resolverip} EMPTY"
            return 1
        elif [[ ${#a[@]} -ne 2 ]]; then
            echo "DOWN ${resolverip} INCOMPLETE ${#a[@]}"
            return 1
        elif [[ ${a[0]%% *} != "ns1.google.com." ]]; then
            echo "DOWN ${resolverip} BOGUS_SOA \"${a[0]}\""
            return 1
        elif [[ ${a[1]} != "dns.google." ]]; then
            echo "DOWN ${resolverip} BOGUS_PTR \"${a[1]}\""
            return 1
        fi
    else
        echo "DOWN ${resolverip} TIMEOUT"
        return 1
    fi
    # Make sure there isn't DNS poisoning
    if s=$(dig @${resolverip} +short +timeout=5 "${sketchy[@]/#/${random_sub}.}"); then
        if [[ -n ${s} ]]; then
            echo "DOWN ${resolverip} BOGUS_POISON \"${s}\""
            return 1
        fi
    else
        echo "DOWN ${resolverip} TIMEOUT_POISON"
        return 1
    fi
    echo "UP ${resolverip}"
}
export -f doit

read -r -a ips < <(xargs < "${INPUT_FILE}")
parallel -j${JOBS} doit ::: "${ips[@]}" ::: ${BASE_DOMAIN} ::: ${STATIC_IP} ::: ${RANDOM_SUB} \
    | tee ${TMPFILE}
echo "Removed ${PIPESTATUS[0]} of $(wc -l ${TMPFILE} | cut -f1 -d' ') servers from list."
grep UP ${TMPFILE} \
    | cut -f2 -d' ' \
    | sort | uniq | sort -V > ${OUTPUT_FILE}
