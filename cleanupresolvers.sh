#!/bin/bash

set -e

JOBS=20
FILE=${1:-$HOME/projects/sec/massdns/lists/resolvers.txt}

# There are around 900 resolvers in the original resolvers.txt, this method should be fine...
# https://stackoverflow.com/questions/17307800/how-to-run-given-function-in-bash-in-parallel/17316302

doit(){
    local resolverip="$1"
    if ! ping -n -c1 "${resolverip}" &>/dev/null; then
        echo "DOWN ${resolverip} PING"
        return 1
    fi

    if dig +timeout=1 google.com @"${resolverip}" &>/dev/null; then
        echo "UP ${resolverip}"
    else
        echo "DOWN ${resolverip} DNS"
        return 1
    fi
    return 0
}

cd $HOME/projects/sec/autoaim/

export -f doit
mapfile -t ips < <(cat "${FILE}" | xargs | tr ' ' $'\n')
parallel -j"${JOBS}" doit ::: "${ips[@]}" \
    | tee raw_resolvers.txt
grep UP raw_resolvers.txt \
    | cut -f2 -d' ' \
    | sort -nu > resolvers.txt
