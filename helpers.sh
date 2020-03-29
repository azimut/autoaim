#!/bin/bash

#==================================================
# Pure - Non env dependent
#==================================================
trim(){ awk '{$1=$1};1' /dev/stdin; }
printfnumber(){
    LC_NUMERIC=en_US printf "%'.f\n" "${1}"
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
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}
#==================================================
# Impure - Depends on network
#==================================================
get_wildcards(){
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
is_port_open(){
    local port="${1}"
    local host="${2}"
    nmap -sT -n -oG - -p"${port}" "${host}" \
        | grep -F /open/
}
#==================================================
# Impure - Depends on file
#==================================================
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
