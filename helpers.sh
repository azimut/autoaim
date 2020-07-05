#!/bin/bash

UA="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0"

DATE=$(date +%s)

AQUATONE=$HOME/projects/sec/aquatone/aquatone
MASSDNS=$HOME/projects/sec/massdns
AUTOAIM=$HOME/projects/sec/autoaim
NMAP=/usr/local/bin/nmap

RESOLVERS=$HOME/projects/sec/autoaim/data/resolvers.txt

#==================================================
# Pure - Non env dependent
#==================================================
join_by() { local IFS="$1"; shift; echo "$*"; }
prefix(){ sed 's#^#'"${1}"'#g' /dev/stdin; }
suffix(){ sed 's#$#'"${1}"'#g' /dev/stdin; }
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
    jq -r "${filter}" < /dev/stdin 2>>${HOME}/jq.err.log
}
massdns_inline(){
    local type="${1}"
    local concurrency="${2:-20}"
    $MASSDNS/bin/massdns -s ${concurrency} \
                         --retry REFUSED \
                         -c 25 \
                         -o J \
                         -l ${HOME}/massdns.err.log \
                         -t ${type} \
                         -r ${RESOLVERS} \
                         -w /dev/stdout \
                         /dev/stdin \
        | jq -r -R 'fromjson?' 2>>${HOME}/jq.err.log | jq_inline "${type}"
}
#==================================================
# Impure - Depends on file
#==================================================
grepdomain(){
    grep -E -I -h -o '[-_[:alnum:]\.]+\.'${1} -r . \
        | sed 's/^2F//g' \
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
isvalidxml(){
    local file="${1}"
    xmllint --format "${file}" &>/dev/null
}
intersection(){
    [[ $# -ne 2 ]] && { ferror "needs 2 arguments"; return 1; }
    [[ (-f $1 || -p $1) && (-f $2 || -p $2) ]] || { ferror "arguments need to be a file"; return 1; }
    local filea="$1"
    local fileb="$2"
    grep -F -xf "$filea" "$fileb"
}
complement(){
    [[ $# -ne 2 ]] && { ferror "needs 2 arguments"; return 1; }
    [[ (-f $1 || -p $1) && (-f $2 || -p $2) ]] || { ferror "arguments need to be a file"; return 1; }
    local filea="$1"
    local fileb="$2"
    grep -F -vxf "$filea" "$fileb"
}
