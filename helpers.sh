#!/bin/bash

RESOLVERS=$HOME/projects/sec/autoaim/resolvers.txt

#==================================================
# Pure - Non env dependent
#==================================================
echoerr(){
    echo "error: $*" 1>&2
}
trim(){ awk '{$1=$1};1' /dev/stdin; }
printfnumber(){
    LC_NUMERIC=en_US printf "%'.f\n" "${1}"
}
explode_domain(){
    local domain="${1}"
    local regex_dot='\.'
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
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}
in_array() {
    local word=$1
    shift
    for e in "$@"; do [[ "$e" == "$word" ]] && return 0; done
    return 1
}
getrandsub(){
    openssl rand -base64 32 | tr -dc 'a-z0-9' | fold -w16 | head -n1
}
#==================================================
# Impure - Depends on network
#==================================================
get_wildcards(){
    local domain="${1}"
    local ips=()
    # NOTE: increase and add more resolvers if more ips are needed
    for _ in {1..5}; do
        ips+=($(dig @8.8.8.8 +short "$(getrandsub).${domain}"))
    done
    if [[ ${#ips[@]} -eq 0 ]]; then
        return 1
    fi
    printf '%s\n' "${ips[@]}" \
        | sort -V \
        | uniq
}
is_port_open(){
    local port="${1}"
    local host="${2}"
    nmap -sT -n -oG - -p"${port}" "${host}" \
        | grep -F /open/
}
jq_inline(){
    local filter=""
    filter=' . | select(.class == "IN")'
    filter+='| (.name|rtrimstr("."))'
    filter+='+ " " + .status + " " + '
    filter+='if .data.answers then (.data.answers[] | { type, data } | join(" "))
             else "   " end'
    jq -r "${filter}" < /dev/stdin
}
massdns_inline(){
    local domain="${1}"
    local type="${2}"
    local concurrency="${3:-20}"
    $MASSDNS/bin/massdns -s ${concurrency} \
                         --retry SERVFAIL,REFUSED \
                         -c 25 \
                         -o J \
                         -t ${type} \
                         -r ${RESOLVERS} \
                         -w /dev/stdout \
                         /dev/stdin \
        | jq_inline "${type}" \
        | tee >(add_dns "${domain}" "${type}")
}
#==================================================
# Impure - Depends on file
#==================================================
grepdomain(){
    local domain="${1}"
    grep -I -E -h -o '[-_[:alnum:]\.]+\.'"${domain}" -r . \
        | sed 's/^32m//g' \
        | sed 's/^253A//g' \
        | sort | uniq
}
grepsubdomain(){
    local domain="${1}"
    grepdomain "${domain}" | sed 's/.'"${domain}"'$//g'
}
upsert_in_file(){
    local file="${1}"
    shift
    local inserts=("${@}")
    if [[ ! -f ${file} ]]; then
        touch ${file}
    fi
    for insert in "${inserts[@]}" ; do
        grep -F -x "${insert}" "${file}" \
            || echo "${insert}" >> "${file}"
    done
}
grepip(){
    grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" /dev/stdin
}
