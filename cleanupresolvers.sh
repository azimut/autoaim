#!/bin/bash

set -e

JOBS=20
FILE=${1:-$HOME/projects/sec/massdns/lists/resolvers.txt}

# There are around 900 resolvers in the original resolvers.txt, this method should be fine...
# https://stackoverflow.com/questions/17307800/how-to-run-given-function-in-bash-in-parallel/17316302

doit(){
    local resolverip="$1"
    local output
    if ! ping -n -c1 "${resolverip}" &>/dev/null; then
        echo "DOWN ${resolverip} PING"
        return 1
    fi
    if output=$(dig +short +timeout=1 PTR 8.8.8.8.in-addr.arpa @"${resolverip}"); then
        if [[ $output != "dns.google." ]]; then
            echo "DOWN ${resolverip} BOGUS_A"
            return 1
        fi
    else
        echo "DOWN ${resolverip} DNS_PTR"
        return 1
    fi
    unset output
    if output=$(dig +short +timeout=1 SOA google.com @"${resolverip}" | cut -f1 -d' '); then
        if [[ $output == "ns1.google.com." ]]; then
            echo "UP ${resolverip}"
            return 0
        else
            echo "DOWN ${resolverip} BOGUS_SOA"
            return 1
        fi
    else
        echo "DOWN ${resolverip} DNS_SOA"
        return 1
    fi
    return 0
}

cd $HOME/projects/sec/autoaim/

export -f doit
mapfile -t ips < <(cat "${FILE}" | xargs | tr ' ' $'\n' | shuf)
parallel -j"${JOBS}" doit ::: "${ips[@]}" \
    | tee raw_resolvers.txt
grep UP raw_resolvers.txt \
    | cut -f2 -d' ' \
    | sort | uniq > resolvers.txt
