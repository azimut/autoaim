#!/bin/bash

set -u

AUTOAIM=$HOME/projects/sec/autoaim

trim(){ awk '{$1=$1};1' /dev/stdin; }
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e ';' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}

#bash "${AUTOAIM}"/cleanupresolvers.sh "${AUTOAIM}"/resolvers.txt

uncomment < domains.txt | trim |
    while read -r domain; do
        mkdir -p ${domain}
        cd ${domain}
        bash ${AUTOAIM}/domain.sh         ${domain}
        bash ${AUTOAIM}/domain-resolve.sh ${domain}
        #bash ${AUTOAIM}/up.sh
        # bash ${AUTOAIM}/scan.sh
        # bash ${AUTOAIM}/screenshot.sh
        #
        bash ${AUTOAIM}/takeover.sh ${domain}
        bash ${AUTOAIM}/second-takeover.sh ${domain}
        cd - &>/dev/null
    done

# bash ${AUTOAIM}/monit.sh
# kill -1 "$(pgrep telegraf)"

bash ${AUTOAIM}/report.sh
