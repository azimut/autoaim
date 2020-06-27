#!/bin/bash

set -euo pipefail

DOMAIN=${1:-${PWD##*/}}
CONCURRENCY=${2:-20}

FOLDER=domains/resolved

mkdir -p ${FOLDER}/

. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

massdns(){
    local type=${1}
    local output=${FOLDER}/${type,,}_${DOMAIN}.json
    rm -f ${output}.gz
    $MASSDNS/bin/massdns \
        -s ${CONCURRENCY} \
        --retry SERVFAIL,REFUSED \
        -c 25 \
        -o J \
        -t ${type} \
        -r ${RESOLVERS} \
        -w ${output} \
        /dev/stdin
    gzip -f ${output}
    massdns_result "${type}" \
        | add_dns "${DOMAIN}" "${type}"
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

# TODO: addback some sort of "purify" deleting NX branches
#       but keeping log of the NX on edges
# Adds RAW subdomains found in the same "project"
mapfile -t domains < <({ grepsubdomain ${DOMAIN}; get_subs; } \
                           | sed 's#$#.'${DOMAIN}'#g'\
                           | unify \
                           | sed 's#.'${DOMAIN}'$##g' \
                           | sed 's#$#.'${DOMAIN}'#g' \
                           | rm_nxdomain ${DOMAIN} \
                           | rm_resolved_wildcards ${DOMAIN} \
                           | sort | uniq \
                           | grep -F ${DOMAIN})
domains+=("${DOMAIN}") # add root domain
printf '%s\n' "${domains[@]}" > asdf.txt
notify-send -t 15000 \
            "Massdns A for ${DOMAIN}" \
            "of $(printfnumber ${#domains[@]}) subdomains..."

printf '%s\n' "${domains[@]}" \
    | massdns A

exit 0

# Gather ips
if [[ -f domains/resolved/a_${DOMAIN}.json.gz ]]; then
    resolved_ips "${DOMAIN}" | add_ips
    resolved_ips "${DOMAIN}" > ips.txt
fi

# Load wildcards
resolved_domains "${DOMAIN}" \
    | rm_nxdomain ${DOMAIN} \
    | rm_resolved_wildcards ${DOMAIN} \
    | wildify \
    | dns_add_wildcard "${DOMAIN}"

# Remove wildcards
mapfile -t domains < <(resolved_domains_nowildcard ${DOMAIN})

notify-send -t 15000 \
            "Massdns of other for ${DOMAIN}" \
            "of $(printfnumber ${#domains[@]}) subdomains..."

# If any NOERROR, try other records
if [[ ${#domains[@]} -gt 0 ]]; then
    printf '%s\n' "${domains[@]}" | massdns AAAA
    printf '%s\n' "${domains[@]}" | massdns NS
    printf '%s\n' "${domains[@]}" | massdns MX
    printf '%s\n' "${domains[@]}" | massdns TXT
fi
# TODO: DNAME, SPF, DMARC, CNAME, ALIAS (i mean if it has it but also has other things)

echo "${0##*/} is DONE!"
