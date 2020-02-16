#!/bin/bash

set -exuo pipefail

OUTPUT_FILE=bounty.conf
BASE_SERVERS=(8.8.8.8 1.1.1.1 9.9.9.9)

trim(){ awk '{$1=$1};1' /dev/stdin; }
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}
grepdomain(){
    egrep -I -h -o '[-_[:alnum:]\.]+\.'${1} -r . \
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
    fgrep -vxf "$filea" "$fileb"
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
find *.*/ -type d -name resolved |
    while read -r rdir; do
        domain=${rdir%/data*}
        domain=${domain#*/}
        cd ${rdir}
        unresolved_domains=(
            $(complement <(grepdomain ${domain}) \
                         <(cd ..; grepdomain ${domain} | grep -v -e scdr.starbucks.co.jp -e admin.login.starbucks.co.jp -e test.istarbucks.co.kr; ) | sort | uniq)
        )
        cd -
        for udomain in ${unresolved_domains[@]}; do
            cat >> ${OUTPUT_FILE} <<EOF
[[inputs.dns_query]]
  interval = "$((40 + $RANDOM % 60))m"
  servers     = ["${BASE_SERVERS[$((RANDOM % 3))]}"]
  record_type = "A"
  domains     = ["${udomain}"]
EOF
        done
    done

# IP: Adds all down ips
find *.*/ -type f -name down.txt -exec cat {} \; | uncomment | trim | sort | uniq |
    while read -r ip; do
        cat >> ${OUTPUT_FILE} <<EOF
[[inputs.ping]]
  interval = "$((40 + $RANDOM % 60))m"
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
