#!/bin/bash

# Used to cleanup wildcard domains from a file. Used mainly for TLDs

set -e
set -x

AUTOAIM=$HOME/projects/sec/autoaim
RESOLVERS="$AUTOAIM/resolvers.txt"
PUBLIC="$AUTOAIM/public_suffix_list.dat"
DOMAIN="$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 12 | head -n 1)"
MASS=${1:-100}
MASSDNS=$HOME/projects/sec/massdns/bin/massdns

uncomment(){ grep -v -e '^$' -e '^#' -e '^//' /dev/stdin; }
prefix(){ sed 's#^#'"${1}"'#g' /dev/stdin; }

$MASSDNS -t A \
         -o S \
         --retry SERVFAIL \
         -c 25 \
         -w "${AUTOAIM}"/massdns_wildcard.txt \
         -s "${MASS}" \
         -r "${RESOLVERS}" \
         <(cat "${PUBLIC}" | uncomment | fgrep -v '*' | prefix "${DOMAIN}.")

fgrep -vxf \
      <(grep $DOMAIN "${AUTOAIM}"/massdns_wildcard.txt | cut -f1 -d' ' | rev | cut -b2- | rev) \
      <(cat "${PUBLIC}" | uncomment | fgrep -v '*' | prefix "${DOMAIN}.") \
    | cut -f2- -d. > "${AUTOAIM}"/clean_public_suffix_list.dat
