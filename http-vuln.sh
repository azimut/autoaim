#!/bin/bash

DOMAIN=${1:-${PWD##*/}}

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

# TODO: add custom template?
get_vuln(){
    echo "SELECT scheme,'://',qheaders->>'Host',path
          FROM http_entries
          WHERE status NOT IN (404,400) -- 301 might be worth looking individually
            AND length!=23" \
                | praw | sed 's#|##g' | sort -u \
                | urinteresting
}
get_vuln
