#!/bin/bash

set -u

AUTOAIM=$HOME/projects/sec/autoaim
FILE=domains.txt

if [[ ! -d ${1} && ( -s ${1} || -p ${1} ) ]]; then
    FILE=${1}
    shift
fi

TASKS=("${@}")

source ${HOME}/projects/sec/autoaim/helpers.sh

#bash "${AUTOAIM}"/cleanupresolvers.sh "${AUTOAIM}"/resolvers.txt

uncomment < ${FILE} | trim |
    while read -r domain; do
        mkdir -p ${domain}
        cd ${domain}
        in_array domain          "${TASKS[@]}" && bash ${AUTOAIM}/domain.sh          ${domain}
        in_array resolve         "${TASKS[@]}" && bash ${AUTOAIM}/domain-resolve.sh  ${domain}
        in_array mx              "${TASKS[@]}" && bash ${AUTOAIM}/mx.sh
        in_array ns              "${TASKS[@]}" && bash ${AUTOAIM}/ns.sh
        in_array takeover        "${TASKS[@]}" && bash ${AUTOAIM}/takeover.sh        ${domain}
        in_array second-takeover "${TASKS[@]}" && bash ${AUTOAIM}/second-takeover.sh ${domain}
        in_array up              "${TASKS[@]}" && bash ${AUTOAIM}/up.sh
        in_array scan            "${TASKS[@]}" && bash ${AUTOAIM}/scan.sh
        in_array screenshot      "${TASKS[@]}" && bash ${AUTOAIM}/screenshot.sh
        cd - &>/dev/null
    done

# bash ${AUTOAIM}/monit.sh
# kill -1 "$(pgrep telegraf)"

in_array report "${TASKS[@]}" && bash ${AUTOAIM}/report.sh
exit 0
