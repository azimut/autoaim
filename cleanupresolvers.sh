#!/bin/bash

# References:
# - https://github.com/vortexau/dnsvalidator

# Can't be nopipefail due parallel returning in the return code the number of failed jobs
set -eu

INPUT_FILE=${1}
JOBS=${2:-20}

BASE_DOMAINS=(starbucks.com.ar) # sites that return the same IP regardless the location, some dns servers might even not be able to reply for a specific TLD
BASE_DOMAIN=${3:-${BASE_DOMAINS[$((RANDOM % ${#BASE_DOMAINS[@]}))]}}
BASE_RESOLVERS=(1.1.1.1 8.8.8.8 9.9.9.9)
BASE_RESOLVER=${BASE_RESOLVERS[$((RANDOM % ${#BASE_RESOLVERS[@]}))]}

STATIC_IP="$(dig +short @${BASE_RESOLVER} ${BASE_DOMAIN})"
RANDOM_SUB="$(openssl rand -base64 32 | tr -dc 'a-z0-9' | fold -w16 | head -n1)"

TMPFILE=raw_${RANDOM}_resolvers.txt
TIMESTAMP="$(date +%s)"

usage() {
	echo "> ./$0 <INPUT_FILE> [CONCURRENCY] [OUTPUT_FILE]"
	echo "INPUT_FILE  plain text with ip adresses of DNS resolvers"
	echo "CONCURRENCY number of threads to run default is ${JOBS}"
	echo "OUTPUT_FILE file where to put the output validated servers default is INPUT_FILE"
}

[[ -s $INPUT_FILE ]] || {
	echo "Invalid INPUT_FILE"
	usage
	exit 1
}

doit() {
	local nameserver="${1}" domain="${2}" ip="${3}" random_sub="${4}"

	local s=""
	# know A
	if s=$(dig @${nameserver} +short +timeout=5 ${domain} A); then
		if [[ ${s} != "${ip}" ]]; then
			printf "%s,DOWN,BOGUS_A,returned %s for %s instead of %s\n" "${nameserver}" "${s}" "${domain}" "${ip}"
			return 1
		fi
	else
		echo "${nameserver},DOWN,TIMEOUT_A"
		return 1
	fi

	local a=()
	# SOA and PTR
	if IFS=$'\n' a=($(dig @${nameserver} +short +timeout=5 google.com SOA 8.8.8.8.in-addr.arpa PTR)); then
		if [[ ${#a[@]} -eq 0 ]]; then
			echo "${nameserver},DOWN,EMPTY_PTR"
			return 1
		elif [[ ${#a[@]} -ne 2 ]]; then
			echo "${nameserver},DOWN,INCOMPLETE_PTR,${#a[@]}"
			return 1
		elif [[ ${a[0]%% *} != "ns1.google.com." ]]; then
			echo "${nameserver},DOWN,BOGUS_SOA,\"${a[0]}\""
			return 1
		elif [[ ${a[1]} != "dns.google." ]]; then
			echo "${nameserver},DOWN,BOGUS_PTR,\"${a[1]}\""
			return 1
		fi
	else
		echo "${nameserver},DOWN,TIMEOUT_PTR"
		return 1
	fi

	# Make sure there isn't DNS poisoning
	local sketchy=(facebook.com paypal.com google.com wikileaks.com)
	if s=$(dig @${nameserver} +short +timeout=5 "${sketchy[@]/#/${random_sub}.}"); then
		if [[ -n ${s} ]]; then
			echo "${nameserver},DOWN,BOGUS_POISON,${s/$'\n'/ }"
			return 1
		fi
	else
		echo "${nameserver},DOWN,TIMEOUT_POISON"
		return 1
	fi
	echo "${nameserver},UP"
}
export -f doit

read -r -a ips < <(xargs <"${INPUT_FILE}")

parallel -j${JOBS} doit ::: "${ips[@]}" ::: ${BASE_DOMAIN} ::: ${STATIC_IP} ::: ${RANDOM_SUB} |
	tee ${TIMESTAMP}_work

echo "Removed ${PIPESTATUS[0]} of $(wc -l ${TMPFILE} | cut -f1 -d' ') servers from list."
grep UP ${TMPFILE} |
	cut -f2 -d' ' |
	sort | uniq | sort -V >${TIMESTAMP}_clean
