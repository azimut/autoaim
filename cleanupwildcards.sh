#!/bin/bash

set -e

AUTOAIM=$HOME/projects/sec/autoaim
RESOLVERS="$AUTOAIM/resolvers.txt"
PUBLIC="$AUTOAIM/clean_public_suffix_list.dat"
DOMAIN="$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 12 | head -n 1)"
MASS=${1:-100}

uncomment(){ grep -v -e '^$' -e '^#' -e '^//' /dev/stdin; }
prefix(){ sed 's#^#'"${1}"'#g' /dev/stdin; }

cd $HOME/projects/sec/massdns

./bin/massdns -t A \
              -o S \
              -w "${AUTOAIM}"/massdns_wildcard.txt \
              -s "${MASS}" \
              -r "${RESOLVERS}" \
              <(cat "${PUBLIC}" | uncomment | fgrep -v '*' | prefix "${DOMAIN}.")

fgrep -vxf \
      <(grep $DOMAIN "${AUTOAIM}"/massdns_wildcard.txt | cut -f1 -d' ' | rev | cut -b2- | rev) \
      <(cat "${PUBLIC}" | uncomment | fgrep -v '*' | prefix "${DOMAIN}.") \
      > "${AUTOAIM}"/clean_public_suffix_list.dat
