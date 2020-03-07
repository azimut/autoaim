#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}
CONCURRENCY=${2:-20}

NMAP=/usr/local/bin/nmap
RESOLVERS=$HOME/projects/sec/autoaim/resolvers.txt
MASSDNS=$HOME/projects/sec/massdns/bin/massdns
FOLDER=data/domains/resolved
SUBDOMAINIZER=$HOME/projects/sec/SubDomainizer/SubDomainizer.py

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

trim(){ awk '{$1=$1};1' /dev/stdin; }
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
has_wildcard(){
    local domain="${1}"
    local ips=()
    # NOTE: increase and add more resolvers if more ips are needed
    for _ in {1..5}; do
        random_sub=$(openssl rand -base64 32 | tr -dc 'a-z0-9' | fold -w16 | head -n1)
        ips+=($(dig @1.1.1.1 +short "${random_sub}.${domain}"))
    done
    if [[ ${#ips[@]} -eq 0 ]]; then
        return 1
    fi
    printf '%s\n' "${ips[@]}" \
        | sort -d \
        | uniq
}

resolved_domains() {
    local domain=${1}
    shift
    local wildcard_ips=("${@}")
    local filename=a_${domain}.txt.gz
    local filepath=${FOLDER}/${filename}
    if [[ -f ${filepath} ]]; then
        if [[ ${#wildcard_ips[@]} -ne 0 ]]; then
            (
                wildcard_grep="${wildcard_ips[*]/%/|}"
                wildcard_grep="${wildcard_grep:0:-1}"
                wildcard_grep="${wildcard_grep// /}"
                zgrep -A7 NOERROR ${filepath} \
                    | grep -B3 -P '(IN A (?!'"${wildcard_grep}"')|IN CNAME (?!'"${wildcard_grep}"'))' \
                    | grep 'IN A$' \
                    | cut -f1 -d' ' \
                    | sort \
                    | uniq
                echo ${domain}.
            ) || true | sort -u
        else
            zgrep -A7 NOERROR ${filepath} \
                | grep -B3 -E 'IN (A|CNAME) ' \
                | grep 'IN A$' \
                | cut -f1 -d' ' \
                | sort \
                | uniq
        fi
    fi
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
grepdomain(){
    grep -E -h -o '[-_[:alnum:]\.]+\.'${1} -r . \
        | sed 's/^32m//g' \
        | sed 's/^253A//g' \
        | sort | uniq
}
grepsubdomain(){
    local domain=${1}
    grepdomain ${domain} | sed 's/.'${domain}'$//g'
}
printfnumber(){
    LC_NUMERIC=en_US printf "%'.f\n" "${1}"
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
    local output=${FOLDER}/${type,,}_${DOMAIN}.txt
    $MASSDNS \
        -s ${CONCURRENCY} \
        --retry SERVFAIL \
        -c 25 \
        -o F \
        -t ${type} \
        -r ${RESOLVERS} \
        -w ${output} \
        <(printf '%s\n' "${domains[@]}" | sort | uniq)
    if [[ ${type} == 'A' ]]; then
        if grep -q -e "IN ${type} " -e 'IN CNAME ' ${output}; then
            grep -e "IN ${type} " -e 'IN CNAME ' ${output} \
                 > ${FOLDER}/short_${type,,}_${DOMAIN}.txt
        fi
    else
        if grep -q "IN ${type} " ${output}; then
            grep "IN ${type} " ${output} \
                 > ${FOLDER}/short_${type,,}_${DOMAIN}.txt
        fi
    fi
    gzip --best -f ${output}
}
explode_domain(){
    local domain="${1}"
    local regex_dot='\.'
    echo ${domain}
    if [[ $domain =~ $regex_dot ]]; then
        explode_domain "${domain#*.}"
    fi
}
explode_domains(){
    local domains=("${@}")
    for domain in "${domains[@]}"; do
        explode_domain "${domain}"
    done
}
port_open(){
    local port=${1}
    local host=${2}
    nmap -sT -n -oG - -p${port} ${host} | grep -F /open/
}

###################################################

# Gave up right away if root domain or subdomain returns SERVFAIL
if dig @1.1.1.1 ${DOMAIN} A | grep SERVFAIL; then
    echo "SERVFAIL returned for ${DOMAIN} giving up"
    echo ${DOMAIN} > data/domains/servfail
    exit 1
fi
if dig @1.1.1.1 $(openssl rand -base64 32 | tr -dc 'a-z0-9' | fold -w16 | head -n1).${DOMAIN} A | grep SERVFAIL; then
    echo "SERVFAIL returned for ${DOMAIN} giving up"
    echo ${DOMAIN} > data/domains/servfail_sub
    exit 1
fi

# Wildcard detection
mapfile -t wildcard_ips < <(has_wildcard ${DOMAIN})
if [[ ${#wildcard_ips[@]} -gt 0 ]]; then
    printf '%s\n' "${wildcard_ips[@]}" > data/domains/wildcards_${DOMAIN}
fi

# Adds subdomains found in the same "project"
subdomains=($({ grepsubdomain ${DOMAIN}; cat ../*/data/sub*; } | sort | uniq))
subdomains=($(explode_domains "${subdomains[@]}" | sort | uniq))
printf '%s\n' "${subdomains[@]}" > ${FOLDER}/raw_subdomains_${DOMAIN}.txt

domains=("${subdomains[@]/%/.${DOMAIN}}")
domains+=("${DOMAIN}")

notify-send -t 15000 \
            "Massdns A for ${DOMAIN}" \
            "of $(printfnumber ${#domains[@]}) subdomains..."
massdns A "${domains[@]}"

# TODO: CNAME domains are missing from IP gather
if compgen -G data/domains/*/short_a_${DOMAIN}.txt; then
    grep -F -h ${DOMAIN} data/domains/*/short_a_${DOMAIN}.txt \
        | grep -F 'IN A ' \
        | cut -f5 -d' ' | sort | uniq | sort -V \
        | tee data/ips.txt
fi

mapfile -t domains < <(resolved_domains ${DOMAIN} "${wildcard_ips[@]}")
# If any NOERROR, try other records
if [[ ${#domains[@]} -gt 0 ]]; then
    massdns AAAA  "${domains[@]}"
    massdns NS    "${domains[@]}"
    massdns MX    "${domains[@]}"
    massdns TXT   "${domains[@]}"
fi
# TODO: DNAME, SPF, DMARC, CNAME, ALIAS (i mean if it has it but also has other things)

if compgen -G data/domains/resolved/short_ns_*; then
    cut -f1,5 -d ' ' < data/domains/resolved/short_ns_* \
        | sort -u |
        while read -r domain ns; do
            graph_trusttrees ${domain}
            dig_axfr         ${domain} ${ns}
            nmap_nsec        ${domain} ${ns}
        done
fi

# Work on resolved domains
printf '%s\n' "${domains[@]}" |
    while read -r domain; do
        if port_open 80 ${domain}; then
            hakrawler     ${domain}
            subdomainizer ${domain}
        fi
    done

# Show Domains that NOERROR that could be bruteforced down
rm -f data/domains/noerror
for ndomain in $(noerror_domains ${DOMAIN}); do
    if grep -q ${ndomain} <(printf '%s\n' "${domains[@]}"); then
        continue
    else
        echo ${ndomain} | tee -a data/domains/noerror
    fi
done
