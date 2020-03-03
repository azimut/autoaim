#!/bin/bash

set -exuo pipefail

DIRS=(${@:-.})
OUTPUT_FILE=bounty.conf
BASE_SERVERS=(8.8.8.8 1.1.1.1 9.9.9.9)
INTERVAL_WIDTH_PING=60
INTERVAL_BASE_PING=60

for dir in "${DIRS[@]}"; do
    [[ ! -d ${dir} ]] && { echo "NOT A DIR!"; exit 1; }
done

grepip(){
    grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" /dev/stdin
}
trim(){ awk '{$1=$1};1' /dev/stdin; }
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
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
grepdomain(){
    grep -E -I -h -o '[-_[:alnum:]\.]+\.'${1} -r . \
        | sed 's/^2F//g' \
        | sed 's/^32m//g' \
        | sed 's/^253A//g' \
        | sort | uniq
}
complement(){
    [[ $# -ne 2 ]] && { ferror "needs 2 arguments"; return 1; }
    [[ (-f $1 || -p $1) && (-f $2 || -p $2) ]] || { ferror "arguments need to be a file"; return 1; }
    local filea="$1"
    local fileb="$2"
    grep -F -vxf "$filea" "$fileb"
}

cat > ${OUTPUT_FILE} <<EOF
[agent]
  interval       = "5m"
  omit_hostname  = true
EOF

# DNS: ADD all unresolved domains
#      Assumes some dir structure...
# (scdr|admin.login).starbucks.co.jp returns NOERROR not NXDOMAIN???
# test.istarbucks.co.kr NOERROR due one of the NS servers is missing the record
# rekindle.starbucks.ca NOERROR due has only NS defined
# find *.*/ -type d -name resolved |
#     while read -r rdir; do
#         domain=${rdir%/data*}
#         domain=${domain#*/}
#         cd ${rdir}
#         unresolved_domains=(
#             $(complement <(resolved_domains ${domain}) \
#                          <(cd ..; grepdomain ${domain} | grep -F -v -e scdr.starbucks.co.jp -e admin.login.starbucks.co.jp -e test.istarbucks.co.kr -e rekindle.starbucks.ca; ) | sort | uniq)
#         )
#         cd -
#         for udomain in "${unresolved_domains[@]}"; do
#             cat >> ${OUTPUT_FILE} <<EOF
# [[inputs.dns_query]]
#   interval = "$((40 + $RANDOM % 60))m"
#   servers     = ["${BASE_SERVERS[$((RANDOM % 3))]}"]
#   record_type = "A"
#   domains     = ["${udomain}"]
# EOF
#         done
#     done

# IP: Adds all down ips
find "${DIRS[@]}" -type f -name down | grepip | sort -V |
    while read -r ip; do
        cat >> ${OUTPUT_FILE} <<EOF
[[inputs.ping]]
  interval = "$((INTERVAL_BASE_PING + RANDOM % INTERVAL_WIDTH_PING))m"
  urls     = ["${ip}"]
  count    = 1
  method   = "native"
EOF
    done

# Alerts
cat >> ${OUTPUT_FILE} <<EOF
# TCP
[[outputs.exec]]
  command = ["xargs","-n1","-I{}","notify-send","--urgency=critical","VICTIM","{}"]
  namepass = ["*net_response"]
  [outputs.exec.tagpass]
    result = ["success"]

# DNS
[[outputs.exec]]
  command   = ["xargs","-n1","-I{}","notify-send","--urgency=critical","dead DNS now resolves","{}"]
  namepass  = ["dns_query"]
  fieldpass = ["query_time_ms"]

# PING
[[outputs.exec]]
  command = ["xargs","-n1","-I{}","notify-send","--urgency=critical","dead IP is back online","{}"]
  namepass = ["ping"]
  fieldpass = ["ttl"]

[[outputs.file]]
  files = ["stdout"]
EOF
