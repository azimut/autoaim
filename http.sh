#!/bin/bash
# https://github.com/tomnomnom/hacks/tree/master/waybackurls
# https://github.com/tomnomnom/hacks/tree/master/urinteresting
#
# HTTP Proxy:
#   Request:  IP - Port - Host - Path - URL
#   Response: Headers - Code - Content (hash?, content length, js content?)
#   Cache: ?, drop responses we know are 404 OR already done
# DB:
# - ip-port-domain
# - domain-path
# HTTP:
# IP/Port/Domain/path/url/parameters
#        //Service
#               // robots.txt
#               // Cross Domain Policy
#                    //Methods
#                    //Headers
#                          // Length
#                          // Mime Type
#                          // Title
#                          // file by extension
#                          // file backup files

DOMAIN=${1:-${PWD##*/}}

SUBDOMAINIZER=$HOME/projects/sec/SubDomainizer/SubDomainizer.py
NIKTO=$HOME/projects/sec/nikto/program/nikto.pl

FOLDER=http
mkdir -p ${FOLDER}/SubDomainizer
mkdir -p ${FOLDER}/hakrawler
mkdir -p ${FOLDER}/nikto

[[ -f ../env.sh ]] && source ../env.sh
. ${HOME}/projects/sec/autoaim/helpers.sh
. ${HOME}/projects/sec/autoaim/persistence.sh

# if is_port_open 8080 127.0.0.1; then
#     export http_proxy=http://127.0.0.1:8080
#     export https_proxy=http://127.0.0.1:8080
# fi

# To any resolved subdomain
subdomainizer(){
    local domain=${1}
    file=${FOLDER}/SubDomainizer/sub_${domain}.txt
    if [[ ! -f ${file} ]]; then
        #-g -gt $GITHUB_TOKEN # it is buggy
        timeout --signal=9 120 \
                python3 ${SUBDOMAINIZER} \
                -k \
                --url ${domain} \
                -o ${file} 2>&1 | tee ${FOLDER}/SubDomainizer/all_${domain}.txt
    fi
}

build_url(){
    local port="${1}" proto="${2}" domain="${3}"
    local url="${proto}://${domain}"
    if [[ ${port} -ne 80 && ${port} -ne 443 ]]; then
        url+=":${port}"
    fi
    echo ${url}
}
nmap_http(){
    scripts=(
        http-useragent-tester       # diff responses with different User-Agents set
        http-mobile-version-checker # diff response on mobile User-Agent

        http-auth                   # parses 401 pages header for auth method
        http-internal-ip-disclosure # sends incomplete HTTP/1.0 without server (always on HTTP)
        http-cors                   # sends different headers on OPTIONS to get domains with CORS?
        http-csrf                   # tries to exploit <forms> for CSRF

        http-chrono               # response time over several requests (adds a param to avoid cache)
        http-aspnet-debug         # tries DEBUG
        http-trace                # tries TRACE
        http-svn-enum             # tries PROPFIND
        http-svn-info             # tries PROPFIND
        http-mcmp                 # tries PING
        http-methods              # tries GET/POST/OPTIONS/HEAD

        http-favicon              # get /favicon.ico
        http-robots.txt           # get /robots.txt
        http-php-version          # get /?PHP=.......
        http-trane-info           # get /evox/about
        http-cross-domain-policy  # get /crossdomain.xml and /clientaccesspolicy.xml
        http-avaya-ipoffice-users # get /system/user/scn_user_list
        http-qnap-nas-info        # get /cgi-bin/authLogin.cgi
        http-git                  # get /.git/head
        http-apache-server-status # get /server-status

        http-passwd               #Xgets different paths trying path transversal
        http-apache-negotiation   # gets different paths below in root
        http-devframework         # gets different paths to identify a dev framework tech
        http-userdir-enum         # gets different home paths at /~<USERNAME>
        http-cakephp-version      # gets different files
        http-config-backup        #+gets different paths(breaks...)
        http-backup-finder        # gets for some backup extensions/prefix

        http-cisco-anyconnect     # greps info from headers
        http-bigip-cookie         # greps cookie on BigIP homepage in /
        http-feed                 # greps feeds in /
        http-title                # greps <title> in /
        http-affiliate-id         # greps api-keys in /
        http-date                 # greps Date header in /
        http-cookie-flags         # greps cookies without httponly flag
        http-webdav-scan          # greps headers on an OPTIONS
        http-gitweb-projects-enum # greps projects
        http-ls                   # greps directory index

        http-errors               # spider forpages returing an error code >400
        http-exif-spider          # spider reading jpg exif data (broken?)
        http-grep                 # spider greps emails,ips,phone or custom
        http-comments-displayer   # spider greps comments
        http-jsonp-detection      #+spider gets trying to get paths with jsonp
        http-open-redirect        # spider greps for open redirects
        http-referer-checker      # spider greps for external script
        http-auth-finder          # spider looking for 401 return code
        http-sitemap-generator    # spider and lists dirs
    )
}
# To any resolved subdomain
hakrawler(){
    local port="${1}" proto="${2}" domain="${3}"
    local url; url="$(build_url ${port} ${proto} ${domain})"
    local file=${FOLDER}/hakrawler/out_${domain}_${port}.txt
    if [[ ! -f ${file} ]]; then
        (
            timeout 240 hakrawler \
                    -insecure \
                    -usewayback \
                    -scope subs \
                    -linkfinder \
                    -depth 3 \
                    -plain \
                    -url ${url} 2>&1 \
                | tee ${file}
        )
    fi
}
niktosite(){
    local plugins=(
        msgs outdated parked robots # greps
        apacheusers negotiate httpoptions clientaccesspolicy favicon sitefiles # gets
    )
    [[ ${#} -ne 4 ]] && return 1
    niktoweb ${*} '/' 'site' "${plugins[@]}"
}
niktourl(){
    local plugins=(
        auth content_search cookies paths siebel # greps
        headers
    )
    niktoweb ${*} 'url' "${plugins[@]}"
}
# Note: works with ip=vhost too.
# -Display V
niktoweb(){
    local port="${1}" proto="${2}" vhost="${3}" ip="${4}" root="${5}" scan="${6}"
    shift;shift;shift;shift;shift;shift
    local plugins=("${@}"); plugins+=(report_text)
    local ssl; [[ ${proto} == "https" ]] && ssl='-ssl' || ssl='-nossl'
    local encoded; encoded="$(base64 <<< "${root}" | sed 's#=*$##g')"
    local file=${FOLDER}/nikto/run_${port}_${proto}_${vhost}_${ip}_${encoded}_${scan}.log
    if [[ ! -f ${file} ]] ; then
        proxychains $NIKTO -Plugins "$(join_by ';' "${plugins[@]}")" \
                    -ask no -nointeractive \
                    -useragent "${UA}" \
                    -F txt -output ${file} \
                    -Cgidirs none \
                    -Tuning x123456789abcde \
                    ${ssl} -vhost ${vhost} -port ${port} -host ${ip} -root ${root}
    fi
}

get_proto(){
    [[ ${1} == *https* || ${1} == "ssl/http" ]] &&  echo 'https' || echo 'http'
}

scan_report_no_waf "${DOMAIN}" | grep -F http |
    while IFS='|' read -r _ ip host _ port _ service _; do
        niktosite ${port} "$(get_proto ${service})" ${host} ${ip}
        #niktourl  ${port} "$(get_proto ${service})" ${host} ${ip} '/'
        #niktosite ${port} "$(get_proto ${service})" ${ip}   ${ip}
    done

#niktourl  80 http starbucks.com.ar 98.99.252.176
#niktosite 80 http starbucks.com.ar 98.99.252.176
#niktosite 80 http 98.99.252.176    98.99.252.176

# # TODO: do port 443
# # Work on resolved domains
# for domain in "${domains[@]}"; do
#     hakrawler     ${domain}
#     #subdomainizer ${domain}
# done
