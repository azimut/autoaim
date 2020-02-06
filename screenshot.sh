#!/bin/sh

# TODO: Might be approach is wrong and aquatone can resume...
#       I know it won't mind re-scanning a domain so I guess
#       I just need to keep processed thing
# TODO: detect per port completion
# TODO: estimate timeout values?

AQUATONE=$HOME/projects/sec/aquatone/aquatone
#DATE=$(date +%s)
FOLDER=data/aquatone #/${DATE}

trim(){ awk '{$1=$1};1' /dev/stdin ; }
separator(){ printf '=%.0s' {0..30}; echo; }

ips_processed(){
    cat data/aquatone/aquatone_urls.txt \
        | cut -f3- -d/ \
        | cut -f1 -d/ \
        | trim | sort | uniq
}

ips_with_open_ports(){
    egrep -l '(80|443)/open/' data/*/*gnmap \
        | cut -f2 -d/ | trim
}

ips_pending(){
    fgrep -vxf <(ips_processed) \
          <(ips_with_open_ports)
}

pending=($(ips_pending))

if [[ ${#pending[@]} -ne 0 ]]; then
    separator
    echo "Processing ${#pending[@]} ips..."
    notify-send -t 10000 "Aquatone" "Processing ${#pending[@]} ips.."
    separator
    mkdir -p ${FOLDER}
    printf '%s\n' ${pending[@]} | \
        $AQUATONE -screenshot-timeout 60000 \
                  -scan-timeout 1000 \
                  -debug \
                  -ports 80,443 \
                  -threads 1 \
                  -out ${FOLDER}
fi
