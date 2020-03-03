#!/bin/bash

set -e
set -x
set -u

DOMAIN=${1}
CONCURRENT=${2:-100}

RESOLVERS=$HOME/projects/sec/autoaim/resolvers.txt
MASSDNS=$HOME/projects/sec/massdns/bin/massdns
DICTIONARY=$HOME/projects/sec/86a06c5dc309d08580a018c66354a056/all.txt
FOLDER=data/domains/brute
STATUS_FILE=${FOLDER}/lastprocessed_${DOMAIN}

mkdir -p ${FOLDER}
suffix(){ sed 's#$#'"${1}"'#g' /dev/stdin; }
split_dictionary()
{
    local dir=${DICTIONARY%/*}
    [[ -f ${dir}/x00 ]] &&
        return 0
    cd ${dir}
    split -d -n 100 ${DICTIONARY}
    cd -
}

split_dictionary

if [[ -f ${STATUS_FILE} && ! -s ${STATUS_FILE} ]]; then
    echo "All domains were processed already"
    exit 0
fi

if [[ -f ${STATUS_FILE} ]]; then
    n_files_processed=$(wc -l ${STATUS_FILE} | cut -f1 -d' ')
else
    n_files_processed=0
fi

all_files=(${DICTIONARY%/*}/x*)
files_to_process=(${all_files[@]:${n_files_processed}})

for file in ${files_to_process[@]}; do
    output="${FOLDER}/resolved_${file##*/}_${DOMAIN}"
    $MASSDNS -s ${CONCURRENT} \
             -t A \
             -w "${output}" \
             -o S \
             -r ${RESOLVERS} \
             <(cat ${file} | suffix ."${DOMAIN}")
    n_domains_found="$(wc -l ${output} | cut -f1 -d' ')"
    if [[ $n_domains_found -gt 0 ]] ; then
        notify-send -t 10000 "MassDNS" "Found ${n_domains_found} subdomains!"
    fi
    echo ${file} >> ${STATUS_FILE}
done
> ${STATUS_FILE}
