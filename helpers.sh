#!/bin/bash

export UA="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0"

export DATE=$(date +%s)

export AMASS=$HOME/projects/sec/amass/amass
export AQUATONE=$HOME/projects/sec/aquatone/aquatone
export AUTOAIM=$HOME/projects/sec/autoaim
export BESTWHOIS=$HOME/projects/sec/bestwhois/bestwhois
export BING=$HOME/projects/sec/bing-ip2hosts/bing-ip2hosts
export GRAFTCP=$HOME/projects/graftcp-master/graftcp
export MASSDNS=$HOME/projects/sec/massdns
export NIKTO=$HOME/projects/sec/nikto/program/nikto.pl
export ONEFORALL=$HOME/projects/sec/OneForAll/oneforall/oneforall.py
export SUBDOMAINIZER=$HOME/projects/sec/SubDomainizer/SubDomainizer.py
export NMAP=/usr/local/bin/nmap

export RESOLVERS=$HOME/projects/sec/autoaim/data/resolvers.txt

#==================================================
# Pure - Non env dependent
#==================================================
join_by() { local IFS="$1"; shift; echo "$*"; }
export -f join_by
prefix(){ sed 's#^#'"${1}"'#g' /dev/stdin; }
suffix(){ sed 's#$#'"${1}"'#g' /dev/stdin; }
echoerr(){
    echo "error: $*" 1>&2
}
trim(){ awk '{$1=$1};1' /dev/stdin; }
printfnumber(){
    LC_NUMERIC=en_US printf "%'.f\n" "${1}"
}
explode_domain(){
    local domain="${1}"
    local regex_dot='\.'
    if [[ $domain =~ $regex_dot ]]; then
        explode_domain "${domain#*.}"
    fi
}
explode_domains(){
    local domains=("${@}")
    for domain in "${domains[@]}"; do
        explode_domain "${domain}"
    done
}
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e '^;;' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}
in_array() {
    local word=$1
    shift
    for e in "$@"; do [[ "$e" == "$word" ]] && return 0; done
    return 1
}
getrandsub(){
    openssl rand -base64 32 | tr -dc 'a-z0-9' | fold -w16 | head -n1
}
#==================================================
# Impure - Depends on network
#==================================================
get_wildcards(){
    local domain="${1}"
    local ips=()
    # NOTE: increase and add more resolvers if more ips are needed
    for _ in {1..5}; do
        ips+=($(dig @8.8.8.8 +short "$(getrandsub).${domain}"))
    done
    if [[ ${#ips[@]} -eq 0 ]]; then
        return 1
    fi
    printf '%s\n' "${ips[@]}" \
        | sort -V \
        | uniq
}
is_port_open(){
    local port="${1}"
    local host="${2}"
    nmap -sT -n -oG - -p"${port}" "${host}" \
        | grep -F /open/
}
jq_inline(){
    local filter=""
    filter=' . | select(.class == "IN")'
    filter+='| (.name|rtrimstr("."))'
    filter+='+ " " + .status + " " + '
    filter+='if .data.answers then (.data.answers[] | { type, data } | join(" "))
             else "   " end'
    jq -r "${filter}" < /dev/stdin 2>>${HOME}/jq.err.log
}
massdns_inline(){
    local type="${1}"
    local concurrency="${2:-20}"
    $MASSDNS/bin/massdns -s ${concurrency} \
                         --retry REFUSED \
                         -c 25 \
                         -o J \
                         -l ${HOME}/massdns.err.log \
                         -t ${type} \
                         -r ${RESOLVERS} \
                         -w /dev/stdout \
                         /dev/stdin \
        | jq -r -R 'fromjson?' 2>>${HOME}/jq.err.log | jq_inline "${type}"
}
#==================================================
# Impure - Depends on file
#==================================================
grepdomain(){
    grep -E -I -h -o '[-_[:alnum:]\.]+\.'${1} -r . \
        | sed 's/^2F//g' \
        | sed 's/^32m//g' \
        | sed 's/^253A//g' \
        | sort | uniq
}
grepsubdomain(){
    local domain="${1}"
    grepdomain "${domain}" | sed 's/.'"${domain}"'$//g'
}
upsert_in_file(){
    local file="${1}"
    shift
    local inserts=("${@}")
    if [[ ! -f ${file} ]]; then
        touch ${file}
    fi
    for insert in "${inserts[@]}" ; do
        grep -F -x "${insert}" "${file}" \
            || echo "${insert}" >> "${file}"
    done
}
grepip(){
    grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" /dev/stdin
}
isvalidxml(){
    local file="${1}"
    xmllint --format "${file}" &>/dev/null
}
intersection(){
    [[ $# -ne 2 ]] && { ferror "needs 2 arguments"; return 1; }
    [[ (-f $1 || -p $1) && (-f $2 || -p $2) ]] || { ferror "arguments need to be a file"; return 1; }
    local filea="$1"
    local fileb="$2"
    grep -F -xf "$filea" "$fileb"
}
complement(){
    [[ $# -ne 2 ]] && { ferror "needs 2 arguments"; return 1; }
    [[ (-f $1 || -p $1) && (-f $2 || -p $2) ]] || { ferror "arguments need to be a file"; return 1; }
    local filea="$1"
    local fileb="$2"
    grep -F -vxf "$filea" "$fileb"
}
#------------------------------
# HTTP

build_url(){
    local port="${1}" proto="${2}" domain="${3}"
    local url="${proto}://${domain}"
    if [[ ${port} -ne 80 && ${port} -ne 443 ]]; then
        url+=":${port}"
    fi
    echo ${url}
}
get_proto(){
    [[ ${1} == *https* || ${1} == "ssl/http" ]] &&  echo 'https' || echo 'http'
}

get_port(){
    local url=${1}
    local port=""
    port=$(unfurl format '%P' <<< ${url})
    if [[ -z ${port} ]]; then
        [[ ${url} == https* ]] && port=443 || port=80
    fi
    echo ${port}
}
export -f get_port

# Note: works with ip=vhost too.
# -Display V
niktoip(){
    local port="${1}" proto="${2}" vhost="${3}" ip="${4}" root="${5}" scan="${6}" plugins="${7}"
    plugins+=";report_text"
    local ssl; [[ ${proto} == "https" ]] && ssl='-ssl' || ssl='-nossl'
    local encoded; encoded="$(base64 <<< "${root}" | sed 's#=*$##g')"
    local file=${FOLDER}/nikto/run_${port}_${proto}_${vhost}_${ip}_${encoded}_${scan}.log
    if [[ ! -f ${file} ]] ; then
        proxychains -q $NIKTO \
                    -Plugins "@NONE;${plugins}" \
                    -ask no -nointeractive \
                    -useragent "${UA}" \
                    -F txt -output ${file} \
                    -Cgidirs none \
                    -Tuning x123456789abcde \
                    ${ssl} -vhost ${vhost} -port ${port} -host ${ip} -root ${root}
    fi
}
export -f niktoip
niktohost(){
    local host="${1}" scan="${2}" plugins="${3}"
    plugins+=";report_text"
    local ssl; [[ ${host} == https* ]] && ssl='-ssl' || ssl='-nossl'
    local encoded; encoded="$(base64 <<< "${host}" | sed 's#=*$##g')"
    local file=${FOLDER}/nikto/run_${encoded}_${scan}.log
    if [[ ! -f ${file} ]] ; then
        proxychains -q $NIKTO \
                    -Plugins "@NONE;${plugins}" \
                    -ask no -nointeractive \
                    -useragent "${UA}" \
                    -F txt -output ${file} \
                    -Cgidirs none \
                    -Tuning x123456789abcde \
                    ${ssl} -host "${host}"
    fi
}
export -f niktohost
niktocmd(){
    if [[ ${#} -eq 5 ]]; then
        niktoip   ${1} ${2} ${3} ${4} ${5}
    elif [[ ${#} -eq 1 ]]; then
        niktohost ${1}
    fi
}
#----------------------
# TODO: '-depth 1 -scope yolo' to extract external urls
hakrawlerip(){
    local port="${1}" proto="${2}" domain="${3}"
    local url; url="$(build_url ${port} ${proto} ${domain})"
    local file=${FOLDER}/hakrawler/out_${proto}_${domain}_${port}.txt
    if [[ ! -f ${file} ]]; then
        timeout --signal=9 $((60*10)) $GRAFTCP hakrawler \
                -insecure \
                -usewayback \
                -scope subs \
                -linkfinder \
                -depth 10 \
                -url ${url} 2>&1 \
            | tee ${file}
    fi
}
hakrawlerhost(){
    local url="${1}"
    local proto port domain;
    proto=$(unfurl  format '%s' <<< ${url})
    port=$(unfurl   format '%P' <<< ${url})
    domain=$(unfurl format '%d' <<< ${url})
    local file=${FOLDER}/hakrawler/out_${proto}_${domain}_${port}.txt
    if [[ ! -f ${file} ]]; then
        timeout --signal=9 $((60*10)) $GRAFTCP hakrawler \
                -insecure \
                -usewayback \
                -scope subs \
                -linkfinder \
                -depth 10 \
                -url ${url} 2>&1 \
            | tee ${file}
    fi
}
#------------------------------
# TODO: ipv6
nmaprun(){
    local stype="${1}" domainorip="${2}" port="${3}" scripts="${4}"
    local file="${FOLDER}/nmap/${domainorip}_${port}_${stype}"
    [[ -f ${file}.xml ]] && return 0
    proxychains -q -f $AUTOAIM/conf/proxychains.http.conf $NMAP \
                -n \
                -vv -d \
                -sT \
                -oA "${file}" \
                --script="${scripts}" \
                --script-args="http.useragent='${UA}',http.max-cache-size=$((5*1024*1024))" \
                --reason \
                -p"${port}" \
                "${domainorip}" 2>&1 | tee ${FOLDER}/nmap/output_${domainorip}_${port}_${stype}.log
}
export -f nmaprun

nmapruntor(){
    local stype="${1}" domainorip="${2}" port="${3}" scripts="${4}"
    local file="${FOLDER}/nmap/${domainorip}_${port}_${stype}"
    [[ -f ${file}.xml ]] && return 0
    proxychains -q -f $AUTOAIM/conf/proxychains.http_8081.conf $NMAP \
                -n \
                -vv -d \
                -sT \
                -oA "${file}" \
                --script="${scripts}" \
                --script-args="http.useragent='${UA}',http.max-cache-size=$((5*1024*1024))" \
                --reason \
                -p"${port}" \
                "${domainorip}" 2>&1 | tee ${FOLDER}/nmap/output_${domainorip}_${port}_${stype}.log
}
export -f nmapruntor

export http_common=(
    http-auth                    # parses 401 pages header for auth method
    http-server-header           # show Server header for missing -sV
    https-redirect               # show redirect from http to https
    http-security-headers        # show some headers
)
export http_grep=(
    http-affiliate-id            # greps html
    http-bigip-cookie            # greps html
    http-generator               # greps html <meta>
    http-gitweb-projects-enum    # greps html
    http-ls                      # greps html on directory index
    http-title                   # greps html <title>
    http-cisco-anyconnect        # greps Headers
    http-cookie-flags            # greps Headers
    http-date                    # greps Headers
    http-webdav-scan             # greps Headers
)
export http_waf_spider=(
    http-backup-finder           # spider GET some backup extensions/prefix
    http-auth-finder             # spider looking for 401 return code
    http-sitemap-generator       # spider make sitemap
    http-feed                    # spider greps feeds
    http-comments-displayer      # spider greps comments
    http-grep                    # spider greps emails,ips,phone or custom
    http-csrf                    # spider greps forms for CSRF
    http-referer-checker         # spider greps for external script
    http-errors                  # spider for pages returing an error code >400
)
export http_waf_site=(
    http-useragent-tester        # diff responses with different User-Agents set
    http-mobileversion-checker   # diff response on mobile User-Agent
    http-favicon                 # get /favicon.ico
    http-robots.txt              # get /robots.txt
    http-cross-domain-policy     # get /crossdomain.xml and /clientaccesspolicy.xml
    http-open-proxy
)
export http_nowaf_site=(
    http-internal-ip-disclosure  # sends Header incomplete HTTP/1.0 without server
    http-cors                    # sends Header
    http-traceroute              # sends Header(s) Max-Forwards
    http-iis-webdav-vuln         # tries PROPFIND
    http-aspnet-debug            # tries DEBUG
    http-trace                   # tries TRACE
    http-svn-enum                # tries PROPFIND
    http-svn-info                # tries PROPFIND
    http-mcmp                    # tries PING
    http-methods                 # tries GET/POST/OPTIONS/HEAD
    http-put                     # tries PUT (no default file)
)
export http_get_site=(
    http-apache-server-status    # get /server-status
    http-avaya-ipoffice-users    # get /system/user/scn_user_list
    http-git                     # get /.git/head
    http-malware-host            # get /ts/in.cgi?open2
    http-php-version             # get /?PHP=.......
    http-qnap-nas-info           # get /cgi-bin/authLogin.cgi
    http-trane-info              # get /evox/about
    http-waf-fingerprint         # get paths

    http-apache-negotiation      # gets different paths below in root
    http-cakephp-version         # gets different files
    http-config-backup           #+gets different paths(breaks...)
    http-devframework            # gets different paths to identify a dev framework tech, also can spider
    http-enum                    # gets different common paths like nikto
    http-iis-short-name-brute    # gets paths
    http-passwd                  #Xgets different paths trying path transversal
    http-userdir-enum            # gets different paths mod_userdir

    http-adobe-coldfusion-apsa1301
    http-awstatstotals-exec      # exploit
    http-axis2-dir-traversal     # exploit
    http-barracuda-dir-traversal # exploit
    http-dlink-backdoor          # exploit (find backdoor)
    http-domino-enum-passwords
    http-frontpage-login
    http-hp-ilo-info
)
export http_nowaf_spider=(
    http-jsonp-detection         # spider GETs urls with params
    http-open-redirect           # spider exploit
    http-rfi-spider              # spider exploit
    http-sql-injection           # spider exploit
    http-fileupload-exploiter    # spider exploit
    http-unsafe-output-escaping  # spider exploit xss
    http-phpself-xss             # spider exploit xss
    http-stored-xss              # spider exploit xss
    http-dombased-xss            # spider exploit xss
)
