#!/bin/bash

set -u

trim(){ awk '{$1=$1};1' /dev/stdin; }
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e ';' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}

#bash "${AUTOAIM}"/cleanupresolvers.sh "${AUTOAIM}"/resolvers.txt

# Takeover
echo "======== servfail"
find . -name servfail -exec cat {} \;
echo "======== servfail_sub"
find . -name servfail_sub -exec cat {} \;
echo "======== noerror (might contain subdomains hidden)"
find . -name noerror -exec cat {} \;
echo "======== Takeover"
grep -F -h -v 'Not Vulnerable' ./*/data/takeover/*.log \
    | rev | cut -f1,2 -d' ' | rev \
    | sed 's/\]//g' \
    | sort | uniq \
    | sort -k2,2d \
    | column -t -R1,2

# Second-Takeover
echo "========= Second takeover"
grep -F -h -v 'Not Vulnerable' ./*/data/second-takeover/*.log \
    | rev | cut -f1,2 -d' ' | rev \
    | sed 's/\]//g' \
    | sort | uniq \
    | sort -k2,2d \
    | column -t -R1,2
zgrep -A7 NXDOMAIN  ./*/data/second-takeover/a_*.gz | grep 'IN A$'
echo "======== ANY (info)"
cat ./*/data/domains/dig/any_* \
    | uncomment \
    | sed 's/IN//g' \
    | tr -s $'\t' \
    | cut -f1,3,4 -d$'\t' | sort -u | sort -k2,2d -k3,3d -t$'\t' | column -t -s$'\t'
echo "======== AXFR"
find . -name 'axfr*' -exec cat {} \; | uncomment
echo "======== SubDomainizer Secrets"
grep -A100 'I have found some secrets for you' ./*/data/domains/SubDomainizer/all*
echo "======== NMAP"
#head -n2 ./*/data/domains/nmap/*.nmap
grep -A1 ERROR ./*/data/domains/nmap/*.nmap
echo "======== AMASS WHOIS"
find . -name 'whois_*' -exec cat {} \; | uncomment | awk '{print $2;}' | sort -u
echo "======== Trusttress"
echo "sxiv */data/domains/resolved/trusttrees/"
