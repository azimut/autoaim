#!/bin/bash

set -exu

# whois-domain
# shodan-api
# resolveall
# --resolve-all
# dns-client-subnet-scan

## port
# qscan.nse
# banner.nse
# duplicates.nse
# reverse-index.nse
# unusual-port.nse

# some missing searchs
# https://github.com/bit4woo/teemo/

NMAP=/usr/local/bin/nmap
BESTWHOIS=$HOME/projects/sec/bestwhois/bestwhois
AMASS=$HOME/projects/sec/amass/amass
ONEFORALL=$HOME/projects/sec/OneForAll/oneforall/oneforall.py
SUBDOMAINIZER=$HOME/projects/sec/SubDomainizer/SubDomainizer.py
INVENTUS=$HOME/projects/sec/Inventus
FOLDER=data/domains

grepdomain(){
    egrep -h -o '[-_[:alnum:]\.]+\.'${1} -r . \
        | sed 's/^32m//g' \
        | sed 's/^253A//g' \
        | sort | uniq
}
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}
trim(){ awk '{$1=$1};1' /dev/stdin; }

mkdir -p ${FOLDER}/amass
mkdir -p ${FOLDER}/dig
mkdir -p ${FOLDER}/nmap
mkdir -p ${FOLDER}/oneforall
mkdir -p ${FOLDER}/SubDomainizer
mkdir -p ${FOLDER}/hakrawler

whoisxml(){
    local domain=${1}
    local file=data/whoisxml_${domain}.json
    if [[ ! -f ${file} ]]; then
        python3 ${BESTWHOIS} \
                --nocolor \
                --api $WHOISXML_API \
                starbucks.com 2>&1 | tee ${file}
    fi
}

hakrawler(){
    local domain=${1}
    local file=${FOLDER}/hakrawler/out_${domain}.txt
    if [[ ! -f ${file} ]]; then
        timeout 120 hakrawler \
                -scope yolo \
                -linkfinder -depth 3 \
                -url ${domain} 2>&1 | tee ${file}
    fi
}

nmap_domain(){
    local domain=${1}
    file=${FOLDER}/nmap/domain_${domain}
    if [[ ! -f ${file}.gnmap ]]; then
        sudo $NMAP -sn -n -v -Pn \
             --reason \
             --dns-servers 1.1.1.1 \
             --script "dns-check-zone,dns-srv-enum,dns-nsec-enum,dns-nsec3-enum" \
             --script-args "dns-check-zone.domain=${domain},dns-srv-enum.domain=${domain},dns-nsec-enum.domains=${domain},dns-nsec3-enum.domains=${domain}" \
             -oA ${file} \
             1.1.1.1
    fi
}

nmap_ns(){
    local domain=${1}
    dig +short NS ${domain} | uncomment | \
        while read -r ns; do
            file=${FOLDER}/nmap/ns_${ns}_info
            if [[ ! -f ${file}.gnmap ]]; then
                sudo $NMAP -sSUV -p 53 -n -v -Pn \
                     --reason \
                     --script "banner,dns-nsid,dns-recursion" \
                     -oA ${file} \
                     ${ns}
            fi
        done
}
dig_axfr(){
    local domain=${1}
    dig +short NS ${domain} | uncomment | \
        while read -r ns; do
            file=${FOLDER}/dig/axfr_${ns}_${domain}
            if [[ ! -f ${file} ]]; then
                dig AXFR @${ns} ${domain} &> ${file}
                cat ${file}
            fi
        done
}

# NS Subdomains - ANY (mind you...you only get what is on the cache of the NS server ATM )
dig_any(){
    local domain=${1}
    dig +short NS ${domain} | uncomment | \
        while read -r ns; do
            file=${FOLDER}/dig/any_${ns}_${domain}
            if [[ ! -f ${file} ]]; then
                dig ANY @${ns} ${domain} &> ${file}
                cat ${file}
            fi
        done
}

subdomainizer(){
    local domain=${1}
    file=${FOLDER}/SubDomainizer/sub_${domain}.txt
    if [[ ! -f ${file} ]]; then
        #-g -gt $GITHUB_TOKEN # it is buggy
        python3 ${SUBDOMAINIZER} \
                -k \
                --url ${domain} \
                -o ${file} 2>&1 | tee ${FOLDER}/SubDomainizer/all_${domain}.txt
    fi
}
amass_whois(){
    local domain=${1}
    file=${FOLDER}/amass/whois_${domain}
    if [[ ! -f ${file} ]]; then
        $AMASS intel \
               -config ${AMASS%/*}/config.ini \
               -d "${domain}" \
               -v \
               -whois -src \
               -o ${file}
    fi
}

amass_passive(){
    local domain=${1}
    file=${FOLDER}/amass/passive_${domain}
    if [[ ! -f ${file}.txt ]]; then
        $AMASS enum \
               -config ${AMASS%/*}/config.ini \
               -d "${domain}" \
               -v \
               -passive -src \
               -oA ${file}
    fi
}

## OneForAll - minus things on Amass
#
# enable_all_module = False
# enable_partial_module = [
#     ('modules.search'      , 'ask'),
#     ('modules.search'      , 'baidu'),
#     ('modules.search'      , 'bing'),
#     ('modules.search'      , 'duckduckgo'),
#     ('modules.search'      , 'gitee'),
#     ('modules.search'      , 'google'),
#     ('modules.search'      , 'sogou'),
#     ('modules.search'      , 'so'),
#     ('modules.search'      , 'yahoo'),
#     ('modules.search'      , 'yandex'),
#     ('modules.datasets'    , 'ximcx'),
#     ('modules.datasets'    , 'ip138'),
#     ('modules.datasets'    , 'chinaz'),
#     ('modules.intelligence', 'threatminer'),
#     ('modules.check'       , 'csp'),
#     ('modules.check'       , 'cert'),
#     ('modules.check'       , 'cdx'),
#     ('modules.check'       , 'robots'),
#     ('modules.check'       , 'sitemap')
# ]
oneforall(){
    local domain=${1}
    csv=${ONEFORALL%/*}/results/${domain}.csv
    file=${FOLDER}/oneforall/${domain}.csv
    if [[ ! -f ${file} ]]; then
        python3 $ONEFORALL \
                --target="${domain}" \
                --show=True \
                run 2>&1 | tee ${FOLDER}/oneforall/output_${domain}.log
        cp -v ${csv} ${file}
    fi
}

while read -r domain; do
    whoisxml      "${domain}" # whois
    nmap_domain   "${domain}" # srv, nsec      # SUBDOMAINs
    nmap_ns       "${domain}" # nil
    dig_axfr      "${domain}" # axft           # SUBDOMAINs
    dig_any       "${domain}" # any            # SUBDOMAINs or IPs (?)
    oneforall     "${domain}" # passive        # SUBDOMAINS
    subdomainizer "${domain}" # web js crawler # SUBDOMAINs
    hakrawler     "${domain}" # web crawler
    amass_passive "${domain}" # passive        # SUBDOMAINs
    amass_whois   "${domain}" # whois          # DOMAINs
    # Save subdomains
    grepdomain ${domain} \
        | sed 's/'${domain}'$//g' \
        | uncomment \
        | rev | cut -c2- | rev \
        | sort > data/subdomains_${domain}.txt
done < <(echo ${1}) #<(echo starbucks.) #<(cat data/domains.txt | uncomment | trim | grep '.com.sg')

result=""
for dir in data/domains/*/; do
    cd ${dir}
    result+=${dir#data/domains/}
    result+=$(grepdomain ${1} | wc -l)
    result+=$'\n'
    cd -
done
notify-send -t 10000 "Totals" "$(echo "${result}" | sort -k2,2nr -t/ | column -t -s/)"
