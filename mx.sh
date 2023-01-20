#!/bin/bash

set -exuo pipefail

DOMAIN=${1:-${PWD##*/}}

BLACKLISTED_MX_DOMAINS='(mailgun.org|google.com|googlemail.com)'

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

nmap_scripts() {
	local protocols=(ssh ssl smtp pop3 tls imap)
	local output=""
	for protocol in "${protocols[@]}"; do
		output+=" or (*${protocol}* and (discovery or safe or auth))"
	done
	echo "${output}"
}

# BUG: nmap needs separate executions for ipv4/ipv6
nmap_mx() {
	local mx=${1}
	local file
	mkdir -p ../mx/${mx}
	file=../mx/${mx}/nmap6
	isvalidxml "${file}.xml" || rm -f "${file}.xml"
	if [[ ! -f ${file}.xml ]]; then
		sudo $NMAP -n \
			-PE -PS25,465 -PA25 \
			-vv -sTV --reason \
			-oA ${file} \
			-6 \
			--script-args="http.useragent='${UA}'" \
			--resolve-all \
			--script='default or banner or fcrdns'"$(nmap_scripts)" \
			${mx}
	fi
	add_scan_file ${file}
	file=../mx/${mx}/nmap
	isvalidxml "${file}.xml" || rm -f "${file}.xml"
	if [[ ! -f ${file}.xml ]]; then
		sudo $NMAP -n \
			-PE -PS25,465 -PA25 -PP \
			-vv -sTV --reason \
			-oA ${file} \
			--script-args="http.useragent='${UA}'" \
			--resolve-all \
			--script='default or banner or fcrdns'"$(nmap_scripts)" \
			${mx}
	fi
	add_scan_file ${file}
}

for qtype in 'A' 'AAAA'; do
	dns_mx "${DOMAIN}" | cut -f2 -d'|' | sort -u | massdns_inline ${qtype} | add_other ${qtype}
done

dns_mx ${DOMAIN} | cut -f2 -d'|' | sort -u | grep -E -v -e "${BLACKLISTED_MX_DOMAINS}" |
	while read -r mx; do
		nmap_mx ${mx}
	done

echo "${0##*/} is DONE!"
