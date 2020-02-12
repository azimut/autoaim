#!/bin/bash

set -eu

INPUT_FILE=${1:-$HOME/projects/sec/massdns/lists/resolvers.txt}
JOBS=${2:-20}

BASE_DOMAINS=(telegram.com starbucks.com.ar) # sites that return the same IP regardless the location
BASE_DOMAIN=${BASE_DOMAINS[$((RANDOM%${#BASE_DOMAINS[@]}))]}
BASE_RESOLVERS=(1.1.1.1 8.8.8.8 9.9.9.9)
BASE_RESOLVER=${BASE_RESOLVERS[$((RANDOM%${#BASE_RESOLVERS[@]}))]}

STATIC_IP=$(dig +short @${BASE_RESOLVER} ${BASE_DOMAIN})

# There are around 900 resolvers in the original resolvers.txt, this method should be fine...
# https://stackoverflow.com/questions/17307800/how-to-run-given-function-in-bash-in-parallel/17316302

doit(){
    local resolverip="$1"
    local domain="$2"
    local ip="$3"
    local output=""
    local sketchy=(facebook.com paypal.com google.com telegram.com wikileaks.com)
    if IFS=$'\n' output=($(dig @${resolverip} +short +timeout=5 ${domain} A google.com SOA 8.8.8.8.in-addr.arpa PTR)); then
        if [[ -z ${output[@]} ]]; then
            echo "DOWN ${resolverip} EMPTY"
            return 1
        elif [[ ${#output[@]} -ne 3 ]]; then
            echo "DOWN ${resolverip} INCOMPLETE ${#output[@]}"
            return 1
        elif [[ ${output[0]} != ${ip} ]]; then
            echo "DOWN ${resolverip} BOGUS_A \"${output[0]}\" ${domain} ${ip}"
            return 1
        elif [[ ${output[1]%% *} != "ns1.google.com." ]]; then
            echo "DOWN ${resolverip} BOGUS_SOA \"${output[1]}\""
            return 1
        elif [[ ${output[2]} != "dns.google." ]]; then
            echo "DOWN ${resolverip} BOGUS_PTR \"${output[2]}\""
            return 1
        fi
    else
        echo "DOWN ${resolverip} TIMEOUT"
        return 1
    fi
    # Make sure there isn't DNS poisoning
    if output=$(dig @${resolverip} +short +timeout=3 ${sketchy[@]/#/${RANDOM}.}); then
        if [[ -n ${output} ]]; then
            echo "DOWN ${resolverip} BOGUS_POISON \"${output}\""
            return 1
        fi
    else
        echo "DOWN ${resolverip} TIMEOUT_POISON"
        return 1
    fi
    echo "UP ${resolverip} $number"
}

cd $HOME/projects/sec/autoaim/

export -f doit
mapfile -t ips < <(cat "${INPUT_FILE}" | xargs | tr ' ' $'\n')
parallel -j"${JOBS}" doit ::: "${ips[@]}" ::: ${BASE_DOMAIN} ::: ${STATIC_IP} | tee raw_resolvers.txt
grep UP raw_resolvers.txt \
    | cut -f2 -d' ' \
    | sort | uniq | sort -V > resolvers.txt
