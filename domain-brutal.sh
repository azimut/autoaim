#!/bin/bash

set -euo pipefail

DOMAIN=${1}
CONCURRENCY=${2:-20}
RESOLVERS=${3:-$HOME/projects/sec/autoaim/resolvers.txt}

[[ -s ${RESOLVERS} ]] || { echo "invalid resolvers file"; exit 1; }

MASSDNS=$HOME/projects/sec/massdns/bin/massdns
FOLDER=data/domains/brutal
ALTWORDLIST=$HOME/projects/sec/autoaim/alt-words.txt

mkdir -p ${FOLDER}

grepdomain(){
    egrep -h -o '[-_[:alnum:]\.]+\.'${1} -r . \
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
massdns(){
    local type=${1}
    shift
    local domains=($@)
    local output=${FOLDER}/${type,,}_${DOMAIN}.txt
    if [[ ! -f ${output}.gz ]]; then
        $MASSDNS \
            -s ${CONCURRENCY} \
            -o F \
            -t ${type} \
            -r ${RESOLVERS} \
            -w ${output} \
            <(printf '%s\n' ${domains[@]} | sort | uniq)
    fi
    if [[ ${type} == 'A' ]]; then
        grep -e "IN ${type} " -e 'IN CNAME ' ${output} \
            | sort > ${FOLDER}/short_${type,,}_${DOMAIN}.txt
    else
        grep "IN ${type} " ${output} \
            | sort > ${FOLDER}/short_${type,,}_${DOMAIN}.txt
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
    local domains=(${@})
    for domain in ${domains[@]}; do
        explode_domain ${domain}
    done
}

# Adds subdomains found in the same "project"
subdomains=($({ grepsubdomain ${DOMAIN}; cat ../*/data/sub*; } | sort | uniq))
subdomains=($(explode_domains ${subdomains[@]} | sort | uniq))
printf '%s\n' ${subdomains[@]} > ${FOLDER}/raw_subdomains_${DOMAIN}.txt

domains=(${subdomains[@]/%/.${DOMAIN}}
         ${DOMAIN})

domains+=(
    $(goaltdns \
          -l <(printf '%s\n' ${domains[@]}) \
          -w ${ALTWORDLIST})
)

if [[ ! -f $FOLDER/short_a_${DOMAIN}.txt ]]; then
    notify-send -t 10000 \
                "Massdns A" \
                "of $(printfnumber ${#domains[@]}) subdomains..."
    massdns A ${domains[@]}
fi
# Note: This might leave some out...as they might not have A but have other...
domains=($(cut -f1 -d' ' ${FOLDER}/short_a_${DOMAIN}.txt | sort | uniq))
massdns AAAA ${domains[@]}
massdns NS   ${domains[@]}
massdns MX   ${domains[@]}
massdns TXT  ${domains[@]}

# NOTE: after this you can re-run domain.sh/domain-resolve.sh as grepdomain should capture the output of this one.
