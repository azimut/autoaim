#!/bin/bash

set -euo pipefail

DOMAIN=${1:-${PWD##*/}}

FOLDER=domains/resolved
mkdir -p ${FOLDER}/

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

initdb

massdns() {
	local type=${1}
	local concurrency=${2:-20}
	local output=${FOLDER}/${type,,}_${DOMAIN}.json
	rm -f ${output}.gz
	$MASSDNS/bin/massdns \
		-s ${concurrency} \
		--retry REFUSED \
		-c 25 \
		-o J \
		-t ${type} \
		-r ${RESOLVERS} \
		-l ${output}.err \
		-w ${output} \
		/dev/stdin
	gzip -f ${output}
	massdns_result "${type}" | add_dns "${DOMAIN}" "${type}"
}

does_servfail() {
	local domain="${1}"
	if dig @8.8.8.8 "${domain}" A | grep SERVFAIL; then
		echo "SERVFAIL returned for ${domain} giving up"
		echo ${domain} >domains/resolved/servfail
		return 0
	fi
	if dig @8.8.8.8 "$(getrandsub).${domain}" A | grep SERVFAIL; then
		echo "SERVFAIL returned for ${domain} giving up"
		echo ${domain} >domains/resolved/servfail_sub
		return 0
	fi
	return 1
}

massdns_result() {
	local record="${1}"
	local file=domains/resolved/${record,,}_${DOMAIN}.json.gz
	local filter=""
	filter=' . | select(.class == "IN")'
	filter+='  | (.name|rtrimstr("."))'
	filter+=' + " " + .status + " " +'
	filter+=' if .data.answers then (.data.answers[] | { type, data } | join(" ")) else "   " end'
	if [[ -f ${file} ]]; then
		jq -r "${filter}" < <(zcat ${file}) 2>jq.${record}.err
	fi
}

###################################################

does_servfail "${DOMAIN}" && {
	echoerr "servfail"
	exit 1
}

# TODO: addback some sort of "purify" deleting NX branches
#       but keeping log of the NX on edges
# Adds RAW subdomains found in the same "project"
mapfile -t domains < <({
	grepsubdomain ${DOMAIN}
	get_subs_noerror_nowild
} |
	suffix .${DOMAIN} |
	unify |
	sed 's#.'${DOMAIN}'$##g' |
	sort | uniq |
	suffix .${DOMAIN} |
	rm_nxdomain ${DOMAIN} |
	rm_resolved_wildcards ${DOMAIN} |
	grep -F ${DOMAIN})
domains+=("${DOMAIN}") # add root domain

notify-send -t 15000 "Massdns A for ${DOMAIN}" \
	"of $(printfnumber ${#domains[@]}) subdomains..."

printf '%s\n' "${domains[@]}" |
	massdns A

# Gather ips
resolved_ips "${DOMAIN}" |
	tee ips.txt |
	add_ips

# Load wildcards
resolved_domains "${DOMAIN}" |
	tee domains.txt |
	rm_nxdomain ${DOMAIN} |
	rm_resolved_wildcards ${DOMAIN} |
	wildify |
	dns_add_wildcard "${DOMAIN}"

# Remove wildcards
mapfile -t domains < <(resolved_domains_nowildcard ${DOMAIN})

notify-send -t 15000 "Massdns of other for ${DOMAIN}" \
	"of $(printfnumber ${#domains[@]}) subdomains..."

# If any NOERROR, try other records
if [[ ${#domains[@]} -gt 0 ]]; then
	printf '%s\n' "${domains[@]}" |
		tee >(massdns AAAA 10) \
			>(massdns NS 10) \
			>(massdns MX 10) \
			>(massdns TXT 10) >/dev/null
fi
# TOnDO: DNAME, SPF, DMARC, CNAME, ALIAS (i mean if it has it but also has other things)

wait && echo "${0##*/} is DONE!"
