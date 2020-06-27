#!/bin/bash

set -exuo pipefail

OUTPUT_FILE=bounty.conf
BASE_SERVERS=(8.8.8.8 1.1.1.1 9.9.9.9)
INTERVAL_WIDTH_PING=60
INTERVAL_BASE_PING=60

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
get_all_down_ips |
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
  command   = ["xargs","-n1","-I{}","notify-send","--urgency=critical","dead IP is back online","{}"]
  namepass  = ["ping"]
  fieldpass = ["ttl"]

[[outputs.file]]
  files = ["stdout"]
EOF
