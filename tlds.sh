#!/bin/bash

prefix(){ sed 's#^#'"${1}"'#g' /dev/stdin; }
uncomment(){ grep -v -e '^$' -e '^#' -e '^//' /dev/stdin; }

set -e
set -x

[[ $# -eq 0 ]] && { echo "Needs 1 argument, the domain (without .com) target, like \"starbucks\""; exit 1; }

DOMAIN="$1"
CONCURRENT=${2:-500} # default is 10k too many drops methinks
AUTOAIM=$HOME/projects/sec/autoaim
MASSDNS=$HOME/projects/sec/massdns/bin/massdns

cat ${AUTOAIM}/clean_public_suffix_list.dat \
    | prefix ${DOMAIN}. > ${DOMAIN}_tlds.txt

# A
$MASSDNS -w ${DOMAIN}_massdns_simple_a.txt \
         -s ${CONCURRENT} \
         -t A \
         -o F \
         -r ${AUTOAIM}/resolvers.txt \
         ${DOMAIN}_tlds.txt

# NOTE: AAAA ? can happen later as I assume if it has an A it MIGHT have an AAAA

# SOA

$MASSDNS -w ${DOMAIN}_massdns_simple_soa.txt \
         -s ${CONCURRENT} \
         -t SOA \
         --retry SERVFAIL \
         -c 25 \
         -o F \
         -r ${AUTOAIM}/resolvers.txt \
         <(grep ' IN A ' ${DOMAIN}_massdns_simple_a.txt \
               | grep ${DOMAIN} \
               | cut -f1 -d' ')

LANG=en_EN join -1 1 \
    <(grep ' IN A '   ${DOMAIN}_massdns_simple_a.txt   | LANG=en_EN sort) \
    <(grep ' IN SOA ' ${DOMAIN}_massdns_simple_soa.txt | LANG=en_EN sort) \
    | sort -k3,3n \
    | tee ${DOMAIN}_final_a.txt \
    | cut -f1,5,9 -d' ' \
    | sort -k2,2n \
    | column -t

grep CNAME ${DOMAIN}_massdns_simple_a.txt \
    | grep "^${DOMAIN}" \
    | LANG=en_EN sort -k5,5d \
    | tee ${DOMAIN}_final_cname.txt \
    | column -t
