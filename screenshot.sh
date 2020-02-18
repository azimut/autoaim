#!/bin/bash

set -exuo pipefail

AQUATONE=$HOME/projects/sec/aquatone/aquatone
FOLDER=data/aquatone
DATE=$(date +%s)

mkdir -p ${FOLDER}

trim(){ awk '{$1=$1};1' /dev/stdin ; }
ips_with_open_ports(){
    grep -E -l '(80|443|8000|8080)/open/' data/*/*.gnmap \
        | cut -f2 -d/ | trim
}
aquatone_processed_ips(){
    local file=data/aquatone/aquatone_urls.txt
    if [[ -f ${file} ]]; then
        cut -f3 -d/ ${file} | sort | uniq
    fi
}

mapfile -t pending < <(ips_with_open_ports | grep -xvf <(aquatone_processed_ips))

[[ ${#pending[@]} -eq 0 ]] && {
    echo "Nothing pending...exiting"
    exit 0
}

[[ -d ${FOLDER} ]] && mv ${FOLDER} ${FOLDER}.${DATE}

echo "Processing ${#pending[@]} ips..."
notify-send -t 10000 "Aquatone" "Processing ${#pending[@]} ips.."

printf '%s\n' "${pending[@]}" | \
    $AQUATONE -screenshot-timeout 60000 \
              -scan-timeout 1000 \
              -debug \
              -ports 80,443,8000,8080 \
              -threads 1 \
              -out ${FOLDER}
