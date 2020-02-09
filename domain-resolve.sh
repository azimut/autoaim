#!/bin/bash

set -x
set -e
set -u

DOMAIN=${1}
CONCURRENCY=${2:-20}

RESOLVERS=$HOME/projects/sec/autoaim/resolvers.txt
MASSDNS=$HOME/projects/sec/massdns/bin/massdns

suffix(){ sed 's#$#'"${1}"'#g' /dev/stdin; }
grepdomain(){
    egrep -h -o '[-[:alnum:]\.]+\.'${1} -r . \
        | sed 's/^32m//g' \
        | sed 's/^253A//g' \
        | sort | uniq
}

massdns(){
    local type=${1}
    shift
    local domains=($@)
    $MASSDNS \
        -s ${CONCURRENCY} \
        -o Sn \
        -t ${type} \
        -r ${RESOLVERS} \
        -w data/resolved_${type,,}_${DOMAIN} \
        <(printf '%s\n' ${domains[@]} | sort | uniq)
}

# > explode_domain www.google.com
# www.google.com
# www.google
# www
explode_domain(){
    local domain="${1}"
    local regex_dot='\.'
    echo ${domain}
    if [[ $domain =~ $regex_dot ]]; then
        explode_domain "${domain%.*}"
    fi
}
export -f explode_domain

# Adds subdomains found in the same "project"
subdomains=($(grepdomain ${DOMAIN} | sed 's/.'${DOMAIN}'$//g')
            $(cat ../*/data/sub*))
subdomains=( $(printf '%s\n' ${subdomains[@]} | sort | uniq | xargs -n1 -I{} sh -c 'explode_domain {}' | sort | uniq) )
domains=(${subdomains[@]/%/.${DOMAIN}})

massdns A    ${domains[@]}
massdns AAAA ${domains[@]}
massdns NS   ${domains[@]}
massdns MX   ${domains[@]}
massdns TXT  ${domains[@]}

cat data/resolved_a_${DOMAIN} \
    | grep ${DOMAIN%%.*} \
    | grep ' A ' \
    | cut -f3 -d' ' | sort | uniq | sort -n > data/ips.txt

## mightbe.txt
# CNAME of trail
# SPF
