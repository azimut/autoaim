#!/bin/bash

set -u

# TODO: this is am(e)ss ... but who cares it's just a report...well except if i miss something...but then again i am using bash...

trim(){ awk '{$1=$1};1' /dev/stdin; }
uncomment(){
    grep -v -e '^$' -e '^#' -e '^//' -e ';' /dev/stdin \
        | sed -e 's/#.*$//g' \
        | sed -e 's/;;.*$//g'
}

#bash "${AUTOAIM}"/cleanupresolvers.sh "${AUTOAIM}"/resolvers.txt
[[ ! -f domains.txt ]] && { exit 1; }
echo "======== MX down"
grep -i down mx/*/*.gnmap | tr / ' ' | cut -f2,4 -d' ' | sort | uniq | column -t
echo "======== MX unresolved"
grep -F -H 'Failed to resolve' mx/*/*.nmap
echo "======== MX open-relay"
grep -F open-relay mx/*/*.nmap | grep -v failed
echo "======== NS recursion"
grep -F recursion: ns/*/*.nmap
echo "======== NS down"
grep -i down ns/*/*.gnmap | tr / ' ' | cut -f2,4 -d' ' | sort | uniq | column -t
echo "======== NS unresolved"
grep -H 'Failed to resolve' ns/*/*.nmap
echo "======== NS NSEC"
cat ./*/data/domains/nmap/nsec_*.nmap | grep -v -e 'Host is' -e 'Nmap scan report for' -e 'Other addresses' | uncomment
echo "======== NS AXFR"
cat ./*/data/domains/dig/axfr* | uncomment
echo "======== wildcards"
cat ./*/data/domains/wildc* | sort -u
echo "======== servfail"
find . -name servfail -exec cat {} \;
echo "======== servfail_sub"
find . -name servfail_sub -exec cat {} \;
echo "======== noerror (might contain subdomains hidden)"
find . -name noerror -exec cat {} \;
echo "======== Takeover (subjack)"
grep -F -h -v 'Not Vulnerable' ./*/data/takeover/*.log \
    | rev | cut -f1,2 -d' ' | rev \
    | sed 's/\]//g' \
    | sort | uniq \
    | sort -k2,2d \
    | column -t -R1,2
echo "======= Takeover (CNAMEs dangling over all)"
revdomain() {
    while read -r domain; do
        echo $(echo $domain | tr '.' $'\n' | tac | paste -sd'.')
    done < /dev/stdin
}
paste -d' ' <(zgrep -h -F -A7 NXDOMAIN ./*/data/domains/resolved/a_*.txt.gz \
                  | grep -F -A1 'ANSWER SECTION' \
            | grep -F CNAME \
            | cut -f1,4 -d' ') \
      <(zgrep -h -F -A7 NXDOMAIN ./*/data/domains/resolved/a_*.txt.gz \
            | grep -F -A1 'ANSWER SECTION' \
            | grep -F CNAME \
            | cut -f5 -d' ' | revdomain) | sort -k3,3d -t' ' | column -t
echo "========= Second takeover"
grep -F -h -v 'Not Vulnerable' ./*/data/second-takeover/*.log \
    | rev | cut -f1,2 -d' ' | rev \
    | sed 's/\]//g' \
    | sort | uniq \
    | sort -k2,2d \
    | column -t -R1,2
zgrep -A7 NXDOMAIN  ./*/data/second-takeover/a_*.gz | grep 'IN A$'
echo "======== ANY (info)"
# cat ./*/data/domains/dig/any_* \
    #     | uncomment \
    #     | sed 's/IN//g' \
    #     | tr -s $'\t' \
    #     | cut -f1,3,4 -d$'\t' | sort -u | sort -k2,2d -k3,3d -t$'\t' | column -t -s$'\t'
echo "======== SubDomainizer Secrets"
grep -A100 'I have found some secrets for you' ./*/data/domains/SubDomainizer/all*
echo "======== NMAP UDP"
find . -name udp.gnmap -exec sh -c "{ grep /open/ {} | cut -f2,4- -d' ' | sed 's#/open/[^/]*//[^/]*///,*##g' | sed 's#Ignored.*##g' | sed 's#[0-9]*/filtered/[^/]*//[^/]*///,*##g' | sed 's#[0-9]*/closed/[^/]*//[^/]*///,*##g' | sed 's#[0-9]*/open|filtered/[^/]*//[^/]*///,*##g' | sed 's#/open/udp//[^/]*//[^/]*/\,*##g'; }" \; | sort -k1,1V |
    while read -r ip; do
        echo -n $(wc -l < ./ips/${ip%% *}/bing-ip2hosts)". "
        echo -n $(head -n1 < ./ips/${ip%% *}/provider | cut -c1-15)". "
        echo -n $(head -n1 < ./ips/${ip%% *}/ptr)". "
        echo -n $(grep -h -F -I "${ip%% *}" ./*/data/domains/resolved/short_a_* | head -n1 | cut -f1 -d' ').;
        echo " ${ip} "
    done | column -t --table-columns BING,PROVIDER,PTR,DOMAIN,IP,PORTS -R4,6,7,8,9,10,11,12,13,14
echo "======== NMAP TCP"
#head -n2 ./*/data/domains/nmap/*.nmap
#grep -A1 ERROR ./*/data/domains/nmap/*.nmap
find . -name tcp.gnmap -exec sh -c "{ grep /open/ {} | cut -f2,4- -d' ' | sed 's#/open/[^/]*//[^/]*///,*##g' | sed 's#Ignored.*##g' | sed 's#[0-9]*/closed/[^/]*//[^/]*///,*##g' | sed 's#[0-9]*/filtered/[^/]*//[^/]*///,*##g'; }" \; | sort -k1,1V |
    while read -r ip; do
        echo -n $(wc -l < ./ips/${ip%% *}/bing-ip2hosts)". "
        echo -n $(head -n1 < ./ips/${ip%% *}/provider | cut -c1-15)". "
        echo -n $(head -n1 < ./ips/${ip%% *}/ptr)". "
        echo -n $(grep -h -F -I "${ip%% *}" ./*/data/domains/resolved/short_a_* | head -n1 | cut -f1 -d' ').;
        echo " ${ip} "
    done | column -t --table-columns BING,PROVIDER,PTR,DOMAIN,IP,PORTS -R4,6,7,8,9,10,11,12,13,14
echo "======== NMAP FULL"
find . -name full_tcp_version.gnmap -exec sh -c "{ grep /open/ {} | cut -f2,4- -d' ' | sed 's#/open/[^/]*//[^/]*///,*##g' | sed 's#Ignored.*##g' | sed 's#[0-9]*/closed/[^/]*//[^/]*///,*##g' | sed 's#[0-9]*/filtered/[^/]*//[^/]*///,*##g' | sed 's/\n\+/\n/g' | grep -v tcpwrapped | xargs | sed 's#/open/tcp//[^/]*//[^/]*/\,*##g'; }" \; | sort -k1,1V |
    while read -r ip; do
        echo -n $(wc -l < ./ips/${ip%% *}/bing-ip2hosts)". "
        echo -n $(head -n1 < ./ips/${ip%% *}/provider)". "
        echo -n $(head -n1 < ./ips/${ip%% *}/ptr)". "
        echo -n $(grep -h -F -I "${ip%% *}" ./*/data/domains/resolved/short_a_* | head -n1 | cut -f1 -d' ')H;
        echo " ${ip} "
    done | column -t --table-columns BING,PROVIDER,PTR,DOMAIN,IP,PORTS -R4,6,7,8,9,10,11,12,13,14
echo "======== AMASS WHOIS"
cat ./*/data/domains/amass/whois_* | uncomment | awk '{print $2;}' | sort -u
echo "======== EXPIRE DATE (unique)"
jq '.expiresDate' ./*/data/whois* | sort -u
echo "======== Trusttress"
echo "sxiv */data/domains/resolved/trusttrees/"
