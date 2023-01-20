#!/bin/bash

set -exu

# whois-domain
# shodan-api
# resolveall
# --resolve-all
# dns-client-subnet-scan

## port
# qscan.nse
# banner.nse
# duplicates.nse
# reverse-index.nse
# unusual-port.nse

DOMAIN=${1:-${PWD##*/}}

FOLDER=domains
mkdir -p ${FOLDER}/amass
mkdir -p ${FOLDER}/nmap
mkdir -p ${FOLDER}/oneforall

. ${HOME}/projects/sec/autoaim/helpers.sh

# Only main domain, expire time
whoisxml() {
	local domain=${1}
	local file=whoisxml_${domain}.json
	if [[ ! -f ${file} ]]; then
		python3 ${BESTWHOIS} \
			--nocolor \
			--api $WHOISXML_API \
			${domain} 2>&1 | tee ${file}
	fi
}

# address      - with NS
# connectivity - with NS
zonemaster() {
	# elapsed, noprogress
	zonemaster-cli --test address \
		--test connectivity \
		--test consistency \
		--test delegation \
		--test nameserver \
		--level DEBUG --show_level --show_module \
		--elapsed \
		--noprogress \
		--ipv4 --ipv6 ${domain}
}

# To any with NS
nmap_domain() {
	local domain=${1}
	file=${FOLDER}/nmap/domain_${domain}
	if [[ ! -f ${file}.gnmap ]]; then
		sudo $NMAP -sn -n -v -Pn \
			--reason \
			--dns-servers 1.1.1.1 \
			--script "dns-check-zone,dns-srv-enum" \
			--script-args "dns-check-zone.domain=${domain},dns-srv-enum.domain=${domain}" \
			-oA ${file} \
			1.1.1.1
	fi
}

amass_download() {
	local amass='amass_linux_amd64'
	local amass_url="https://github.com/OWASP/Amass/releases/latest/download/${amass}.zip"
	cd ${HOME}/projects/sec
	if ! wget --continue -S "${amass_url}" | grep -F 'HTTP/1.1 416'; then
		rm -rf ./amass
		unzip -e ${amass}.zip
		mv ${amass} amass
	fi
	cd -
}

# Main domain, might be addded back to domains.txt
amass_whois() {
	local domain=${1}
	file=${FOLDER}/amass/whois_${domain}
	if [[ ! -f ${file} ]]; then
		$AMASS intel \
			-config ${AMASS%/*}/config.ini \
			-d "${domain}" \
			-v \
			-whois -src \
			-o ${file}
	fi
}

# Main domain
amass_passive() {
	local domain=${1}
	file=${FOLDER}/amass/passive_${domain}
	if [[ ! -f ${file}.txt ]]; then
		$AMASS enum \
			-config ${AMASS%/*}/config.ini \
			-d "${domain}" \
			-v \
			-passive -src \
			-oA ${file}
	fi
}

## OneForAll - minus things on Amass
#
# enable_all_module = False
# enable_partial_module = [
#     ('modules.search'      , 'ask'),
#     ('modules.search'      , 'baidu'),
#     ('modules.search'      , 'bing'),
#     ('modules.search'      , 'duckduckgo'),
#     ('modules.search'      , 'gitee'),
#     ('modules.search'      , 'google'),
#     ('modules.search'      , 'sogou'),
#     ('modules.search'      , 'so'),
#     ('modules.search'      , 'yahoo'),
#     ('modules.search'      , 'yandex'),
#     ('modules.datasets'    , 'ximcx'),
#     ('modules.datasets'    , 'ip138'),
#     ('modules.datasets'    , 'chinaz'),
#     ('modules.intelligence', 'threatminer'),
#     ('modules.check'       , 'csp'),
#     ('modules.check'       , 'cert'),
#     ('modules.check'       , 'cdx'),
#     ('modules.check'       , 'robots'),
#     ('modules.check'       , 'sitemap')
# ]
oneforall() {
	local domain=${1}
	csv=${ONEFORALL%/*}/results/${domain}.csv
	file=${FOLDER}/oneforall/${domain}.csv
	if [[ ! -f ${file} ]]; then
		python3 $ONEFORALL \
			--target="${domain}" \
			--show=True \
			run 2>&1 | tee ${FOLDER}/oneforall/output_${domain}.log
		cp -v ${csv} ${file}
	fi
}

#amass_download

whoisxml "${DOMAIN}"      # whois
nmap_domain "${DOMAIN}"   # srv, nsec # SUBDOMAINs
oneforall "${DOMAIN}"     # passive   # SUBDOMAINS
amass_passive "${DOMAIN}" # passive   # SUBDOMAINs
amass_whois "${DOMAIN}"   # whois     # DOMAINs

# Report results
result=""
for dir in domains/*/; do
	cd ${dir}
	result+=${dir#domains/}
	result+=$(grepdomain ${DOMAIN} | wc -l)
	result+=$'\n'
	cd -
done
notify-send -t 10000 "Totals" "$(echo "${result}" | sort -k2,2nr -t/ | column -t -s/)"
