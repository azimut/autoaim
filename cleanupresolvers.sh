#!/bin/bash

set -e

# https://stackoverflow.com/questions/17307800/how-to-run-given-function-in-bash-in-parallel/17316302

doit(){
    local resolverip="$1"
    if ! ping -c1 ${resolverip} &>/dev/null; then
        echo "DOWN ${resolverip} PING"
        return 1
    fi

    if dig +timeout=1 +short google.com @${resolverip} &>/dev/null; then
        echo "UP ${resolverip}"
    else
        echo "DOWN ${resolverip} DNS"
    fi
    return 0
}
export -f doit
mapfile -t ips < $HOME/projects/sec/massdns/lists/resolvers.txt
parallel -j10 doit ::: "${ips[@]}"
