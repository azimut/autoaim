#!/bin/bash

set -euo pipefail

DOMAIN=${1:-${PWD##*/}}
CONCURRENCY=${2:-20}

NMAP=/usr/local/bin/nmap
RESOLVERS=$HOME/projects/sec/autoaim/resolvers.txt
MASSDNS=$HOME/projects/sec/massdns
FOLDER=data/domains/resolved
SUBDOMAINIZER=$HOME/projects/sec/SubDomainizer/SubDomainizer.py

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

mkdir -p ${FOLDER}

mkdir -p ${FOLDER}/../SubDomainizer
mkdir -p ${FOLDER}/../hakrawler
mkdir -p ${FOLDER}/../dig
mkdir -p ${FOLDER}/../nmap
mkdir -p ${FOLDER}/../trusttrees

# To any with NS
nmap_nsec(){
    local domain=${1}
    local ns=${2}
    file=${FOLDER}/../nmap/nsec_${domain}_${ns}
    if [[ ! -f ${file}.gnmap ]]; then
        sudo $NMAP -sn -n -v -Pn \
             --reason \
             --dns-servers 1.1.1.1 \
             --script "dns-nsec-enum,dns-nsec3-enum" \
             --script-args "dns-nsec-enum.domains=${domain},dns-nsec3-enum.domains=${domain}" \
             -oA ${file} \
             ${ns}
    fi
}

# To any with NS/sub, assume NS resolves
dig_axfr(){
    local domain=${1}
    local ns=${2}
    dig @1.1.1.1 +short ${ns} A | trim |
        while read -r ip; do
            file=${FOLDER}/../dig/axfr_${ns}_${ip}_${domain}
            if [[ ! -f ${file} ]]; then
                dig @${ip} ${domain} AXFR 2>&1 | tee ${file}
            fi
        done
}

noerror_domains(){
    local domain=${1}
    local filename=a_${domain}.txt.gz
    local filepath=${FOLDER}/${filename}
    if [[ -f ${filepath} ]]; then
        zgrep -A7 NOERROR ${filepath} \
            | grep -B7 'IN SOA' \
            | grep 'IN A' \
            | cut -f1 -d' '
    fi
}
graph_trusttrees(){
    local domain=${1}
    local filename=${domain}_trust_tree_graph.png
    if [[ ! -f ${FOLDER}/../trusttrees/${domain}_trusttrees.log ]]; then
        cd ${FOLDER}/../trusttrees
        trusttrees --gandi-api-v5-key $GANDI_API \
                   --resolvers <(echo -e "8.8.8.8\n1.1.1.1") \
                   --target ${domain} -x png 2>&1 | tee ${domain}_trusttrees.log
        mv output/${filename} .
        rm -rf ./output
        cd -
    fi
}
# To any resolved subdomain
subdomainizer(){
    local domain=${1}
    file=${FOLDER}/../SubDomainizer/sub_${domain}.txt
    if [[ ! -f ${file} ]]; then
        #-g -gt $GITHUB_TOKEN # it is buggy
        timeout --signal=9 120 python3 ${SUBDOMAINIZER} \
                -k \
                --url ${domain} \
                -o ${file} 2>&1 | tee ${FOLDER}/../SubDomainizer/all_${domain}.txt
    fi
}

# To any resolved subdomain
hakrawler(){
    local domain=${1}
    local port=${2-80}
    if [[ ${port} -eq 80 ]]; then
        local url=http://${domain}/
    else
        local url=https://${domain}/
    fi
    local file=${FOLDER}/../hakrawler/out_${domain}_${port}.txt
    if [[ ! -f ${file} ]]; then
        timeout 120 hakrawler \
                -scope yolo \
                -linkfinder -depth 3 \
                -url ${url} 2>&1 | tee ${file}
    fi
}

massdns(){
    local type=${1}
    shift
    local domains=("${@}")
    local output=${FOLDER}/${type,,}_${DOMAIN}.json
    $MASSDNS/bin/massdns \
        -s ${CONCURRENCY} \
        --retry SERVFAIL,REFUSED \
        -c 25 \
        -o J \
        -t ${type} \
        -r ${RESOLVERS} \
        -w ${output} \
        <(printf '%s\n' "${domains[@]}" | sort | uniq)
    gzip -f ${output}
    massdns_result "${type}" | add_dns "${DOMAIN}" "${type}"
}

does_servfail(){
    local domain="${1}"
    if dig @8.8.8.8 "${domain}" A | grep SERVFAIL; then
        echo "SERVFAIL returned for ${domain} giving up"
        echo ${domain} > data/domains/resolved/servfail
        return 0
    fi
    if dig @8.8.8.8 "$(getrandsub).${domain}" A | grep SERVFAIL; then
        echo "SERVFAIL returned for ${domain} giving up"
        echo ${domain} > data/domains/resolved/servfail_sub
        return 0
    fi
    return 1
}

# TODO: add CNAME in massdns query
massdns_result(){
    local record="${1}"
    local file=data/domains/resolved/${record,,}_${DOMAIN}.json.gz
    local filter=""
    filter=' . | select(.class == "IN")'
    filter+='  | (.name|rtrimstr("."))'
    filter+=' + " " + .status + " " +'
    filter+=' if .data.answers then (.data.answers[] | { type, data } | join(" ")) else "   " end'
    if [[ -f ${file} ]]; then
        jq -r "${filter}" < <(zcat ${file})
    fi
}

###################################################

# Gave up right away if ROOT domain or subdomain returns SERVFAIL
does_servfail "${DOMAIN}" && { echoerr "servfail"; exit 1; }

# Adds RAW subdomains found in the same "project"
mapfile -t domains < <({ grepsubdomain ${DOMAIN}; getsubs; } \
                           | sed 's#$#.'"${DOMAIN}"'#g' \
                           | unify \
                           | sed 's#$#.'"${DOMAIN}"'#g' \
                           | rm_nxdomain ${DOMAIN} \
                           | purify \
                           | grep -F ${DOMAIN} \
                           | rm_nxdomain ${DOMAIN})

domains+=("${DOMAIN}") # add root domain

notify-send -t 15000 \
            "Massdns A for ${DOMAIN}" \
            "of $(printfnumber ${#domains[@]}) subdomains..."

massdns A "${domains[@]}"

# Gather ips
if [[ -f data/domains/resolved/a_${DOMAIN}.json.gz ]]; then
    resolved_ips "${DOMAIN}" | add_ips
    resolved_ips "${DOMAIN}" > data/ips.txt
fi

#exit 1

resolved_domains "${DOMAIN}" \
    | wildify \
    | dns_add_wildcard "${DOMAIN}"

#mapfile -t domains < <(resolved_domains_nowildcard ${DOMAIN})

# If any NOERROR, try other records
if [[ ${#domains[@]} -gt 0 ]]; then
    massdns AAAA  "${domains[@]}"
    massdns NS    "${domains[@]}"
    massdns MX    "${domains[@]}"
    massdns TXT   "${domains[@]}"
fi
# TODO: DNAME, SPF, DMARC, CNAME, ALIAS (i mean if it has it but also has other things)

#exit 1

# Work on domains with NS servers
dns_ns "${DOMAIN}" |
    while IFS='|' read -r domain ns; do
        graph_trusttrees ${domain}
        dig_axfr         ${domain} ${ns}
        nmap_nsec        ${domain} ${ns}
    done

exit 1

# Work on resolved domains
printf '%s\n' "${domains[@]}" | uncomment |
    while read -r domain; do
        if is_port_open 80 ${domain}; then
            hakrawler     ${domain}
            subdomainizer ${domain}
        fi
    done

# Show Domains that NOERROR that could be bruteforced down
# rm -f data/domains/noerror
# for ndomain in $(noerror_domains ${DOMAIN}); do
#     if grep -q ${ndomain} <(printf '%s\n' "${domains[@]}"); then
#         continue
#     else
#         echo ${ndomain} | tee -a data/domains/noerror
#     fi
# done
