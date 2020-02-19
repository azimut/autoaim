#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}
CONCURRENCY=${2:-20}

RESOLVERS=$HOME/projects/sec/autoaim/resolvers.txt
MASSDNS=$HOME/projects/sec/massdns/bin/massdns
FOLDER=data/domains/resolved

mkdir -p ${FOLDER}
mkdir -p ${FOLDER}/trusttrees

has_wildcard(){
    local domain="${1}"
    local ips=()
    # NOTE: increase and add more resolvers if more ips are needed
    for x in {1..5}; do
        random_sub=$(openssl rand -base64 32 | tr -dc 'a-z0-9' | fold -w16 | head -n1)
        ips+=($(dig @1.1.1.1 +short "${random_sub}.${domain}"))
    done
    if [[ ${#ips[@]} -eq 0 ]]; then
        return 1
    fi
    mapfile -t unique_ips < <(printf '%s\n' "${ips[@]}" | sort -d | uniq)
    printf '%s\n' "${unique_ips[@]}"
    return 0
}

# TODO: only supports 1 IP to ignore for wildcard
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
                    | grep -B3 -P '(IN A (?!'"${wildcard_grep}"')|IN CNAME )' \
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
    if [[ ! -f ${FOLDER}/trusttrees/${domain}_trusttrees.log ]]; then
        cd ${FOLDER}/trusttrees
        trusttrees --gandi-api-v5-key $GANDI_API \
                   --resolvers <(echo -e "8.8.8.8\n1.1.1.1") \
                   --target ${domain} -x png 2>&1 | tee ${domain}_trusttrees.log
        mv output/${filename} .
        rm -rf ./output
        cd -
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

# Gave up right away if root domain returns SRVFAIL
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

notify-send -t 10000 \
            "Massdns A" \
            "of $(printfnumber ${#domains[@]}) subdomains..."

massdns A "${domains[@]}"
mapfile -t domains < <(resolved_domains ${DOMAIN} "${wildcard_ips[@]}")

if [[ ${#domains[@]} -gt 0 ]]; then
    massdns AAAA "${domains[@]}"
    massdns NS   "${domains[@]}"
    massdns MX   "${domains[@]}"
    massdns TXT  "${domains[@]}"
fi
# DNAME, SPF, DMARC, CNAME (i mean if it has it but also has other things)

# TODO: CNAME domains are missing from IP gather
grep -F -h ${DOMAIN} data/domains/*/short_a_${DOMAIN}.txt \
    | grep -F 'IN A ' \
    | cut -f5 -d' ' | sort | uniq | sort -V \
    | tee data/ips.txt

# CLI command:
# fgrep -h starbucks.fr domains/*/short_a_starbucks.fr.txt | grep CNAME | cut -f1,5 -d' ' | sort | uniq | sort -k2,2d | column -t

# TODO: CNAME domains are missing from trusttrees graph
resolved_domains ${DOMAIN} "${wildcard_ips[@]}" |
    while read -r nsdomain; do
        graph_trusttrees "${nsdomain}"
    done

# Show Domains that NOERROR that could be bruteforced down
rm -f data/domains/noerror
for ndomain in $(noerror_domains ${DOMAIN}); do
    if grep -q ${ndomain} <(resolved_domains ${DOMAIN} "${wildcard_ips[@]}"); then
        continue
    else
        echo ${ndomain} | tee -a data/domains/noerror
    fi
done
