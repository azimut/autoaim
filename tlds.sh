#!/bin/bash

#set -exuo

DOMAIN=${1:-${PWD##*/}}
CONCURRENCY=${2:-50} # default is 10k too many drops methinsk

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

TSD=${DOMAIN%%.*}

tlds=($(prefix ${TSD}. < ${AUTOAIM}/data/clean_public_suffix_list.dat))

for qtype in 'A' 'AAAA' 'SOA'; do
    printf '%s\n' "${tlds[@]}" \
        | rm_nxdomain_tlds \
        | massdns_inline "${qtype}" "${CONCURRENCY}" \
        | add_tld "${DOMAIN}" "${qtype}"
done

echo "${0##*/} is DONE!"
