#!/bin/bash

set -euo pipefail

DOMAIN=${1:-${PWD##*/}}
CONCURRENCY=${2:-20}

RESOLVERS=$HOME/projects/sec/autoaim/resolvers.txt
MASSDNS=$HOME/projects/sec/massdns
FOLDER=domains/resolved

mkdir -p ${FOLDER}/

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

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
        echo ${domain} > domains/resolved/servfail
        return 0
    fi
    if dig @8.8.8.8 "$(getrandsub).${domain}" A | grep SERVFAIL; then
        echo "SERVFAIL returned for ${domain} giving up"
        echo ${domain} > domains/resolved/servfail_sub
        return 0
    fi
    return 1
}

massdns_result(){
    local record="${1}"
    local file=domains/resolved/${record,,}_${DOMAIN}.json.gz
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
mapfile -t domains < <({ grepsubdomain ${DOMAIN}; get_subs; } \
                           | sed 's#$#.'"${DOMAIN}"'#g' \
                           | unify \
                           | sed 's#$#.'"${DOMAIN}"'#g' \
                           | rm_nxdomain ${DOMAIN} \
                           | rm_resolved_wildcards ${DOMAIN} \
                           | grep -F ${DOMAIN})
domains+=("${DOMAIN}") # add root domain

notify-send -t 15000 \
            "Massdns A for ${DOMAIN}" \
            "of $(printfnumber ${#domains[@]}) subdomains..."

massdns A "${domains[@]}"

# Gather ips
if [[ -f domains/resolved/a_${DOMAIN}.json.gz ]]; then
    resolved_ips "${DOMAIN}" | add_ips
    resolved_ips "${DOMAIN}" > ips.txt
fi

# Load wildcards
resolved_domains "${DOMAIN}" \
    | wildify \
    | dns_add_wildcard "${DOMAIN}"

# Remove wildcards
mapfile -t domains < <(resolved_domains_nowildcard ${DOMAIN})

# If any NOERROR, try other records
if [[ ${#domains[@]} -gt 0 ]]; then
    massdns AAAA  "${domains[@]}"
    massdns NS    "${domains[@]}"
    massdns MX    "${domains[@]}"
    massdns TXT   "${domains[@]}"
fi
# TODO: DNAME, SPF, DMARC, CNAME, ALIAS (i mean if it has it but also has other things)
