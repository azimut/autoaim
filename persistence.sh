#!/bin/bash

# TODO: IPs might be should be global (not per schema)
# TODO: save subdomain, domain and SLD+TLD separate
# TODO: add name resolve queries of NS MX to dns_rec
# TODO: rm downip and upip in favor of insert_ip(ip,status)
set -xu

DB=${DB:-postgres}

psimple(){
    psql -U postgres -d ${DB} < /dev/stdin
}
praw(){
    psql -U postgres -d ${DB} -t -A < /dev/stdin
}
pcall(){
    psql -U postgres -d ${DB} < /dev/stdin | grep -F -c CALL || true
}

# cleardb(){
#     echo "
# DROP TABLE IF EXISTS nmap_scan;
# DROP TABLE IF EXISTS tld_records;
# DROP TABLE IF EXISTS dns_a_wildcard;
# DROP TABLE IF EXISTS dns_record;
# DROP TABLE IF EXISTS ip_ptr;
# DROP TABLE IF EXISTS ip_data;
# DROP TABLE IF EXISTS ip_history;
# " | psql -U postgres
# }
initdb(){
    echo "SELECT 'CREATE DATABASE ${DB}' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB}')\gexec" | psql -U postgres -d postgres
    praw < ./sql/create_tables.sql
    praw < ./sql/create_views.sql
}
#------------------------------
add_ips() {
    local ret=""
    while read -r ip; do ret+="CALL insert_ip('${ip}');" ; ret+=$'\n'; done
    echo "${ret}" | pcall
}
add_ips_up() {
    local ret=""
    while read -r ip; do ret+="CALL insert_upip('${ip}');"  ; ret+=$'\n'; done
    echo "${ret}" | pcall
}
add_ips_down() {
    local ret=""
    while read -r ip; do ret+="CALL insert_downip('${ip}');"; ret+=$'\n'; done
    echo "${ret}" | pcall
}
get_ips_up(){
    local root="${1}"
    echo "SELECT recent.ip FROM (
        SELECT ip_history.ip, max(ip_history.timestamp) as mtime
        FROM ip_history
        INNER JOIN dns_record ON (ip_history.ip=dns_record.ip)
        WHERE dns_record.root='${root}'
        GROUP BY ip_history.ip) recent,
  ip_history original
WHERE original.timestamp=recent.mtime
  AND original.ip=recent.ip
  AND original.is_up=true;
" | praw
}
get_ips_down(){
    local root="${1}"
    echo "SELECT recent.ip FROM (
  SELECT ip_history.ip, max(ip_history.timestamp) as mtime
  FROM ip_history
  INNER JOIN dns_record ON (ip_history.ip=dns_record.ip)
  WHERE dns_record.root='${root}'
  GROUP BY ip_history.ip) recent,
  ip_history original
WHERE original.timestamp=recent.mtime
  AND original.ip=recent.ip
  AND original.is_up=false;
" | praw
}
get_ips_unknown(){
    local root="${1}"
    echo "SELECT recent.ip
          FROM
          ( SELECT ip_history.ip,
                   MAX(ip_history.timestamp) AS mtime
            FROM ip_history
            JOIN dns_record ON (ip_history.ip=dns_record.ip)
            WHERE dns_record.root='${root}'
            GROUP BY ip_history.ip) recent,
          ip_history original
          WHERE original.timestamp=recent.mtime
            AND original.ip=recent.ip
            AND original.is_up IS NULL;" | praw
}
get_subs(){
    echo "SELECT DISTINCT ON (sub) sub FROM dns_record" | praw
}
get_subs_noerror(){
    echo "SELECT DISTINCT ON (sub) sub
          FROM dns_record
          WHERE rcode='NOERROR' AND qtype='A'" | praw
}
get_subs_noerror_nowild(){
    echo "SELECT DISTINCT ON (noerror.sub) noerror.sub
          FROM (SELECT name,root,sub,ip
                FROM dns_record
                WHERE rcode='NOERROR' AND qtype='A') noerror
          LEFT JOIN dns_a_wildcard wild
            ON noerror.ip=wild.ip
          WHERE noerror.name!=noerror.root
            AND (wild.ip IS NULL
                 OR (wild.ip IS NOT NULL AND noerror.name=wild.base))" | praw
}
#------------------------------
add_dns(){
    local root="${1}" # for which domain are these subdomains
    local qtype="${2}" # what record type we queried
    local ret=""
    while read -r domain rcode rtype ipordata; do
        if [[ ${qtype} == "${rtype}" ]] && [[ ${rtype} == "A" || ${rtype} == "AAAA" ]]; then
            ipordata="$(purge "${ipordata}")"
            rtype="$(purge "${rtype}")"
            ret+="CALL add_dns('${domain}','${root}','${qtype}',${rtype},'${rcode}',INET ${ipordata});"
            ret+=$'\n'
        else
            ipordata="$(purge "${ipordata}")"
            rtype="$(purge "${rtype}")"
            ret+="CALL add_dns('${domain}','${root}','${qtype}',${rtype},'${rcode}',${ipordata});"
            ret+=$'\n'
        fi
    done
    echo "${ret}" | pcall
}
add_other(){
    local qtype="${1}" # what record type we queried
    local ret=""
    while read -r domain rcode rtype ipordata; do
        if [[ ${qtype} == "${rtype}" ]] && [[ ${rtype} == "A" || ${rtype} == "AAAA" ]]; then
            ipordata="$(purge "${ipordata}")"
            rtype="$(purge "${rtype}")"
            ret+="CALL add_other('${domain}','${qtype}',${rtype},'${rcode}',INET ${ipordata});"
            ret+=$'\n'
        else
            ipordata="$(purge "${ipordata}")"
            rtype="$(purge "${rtype}")"
            ret+="CALL add_other('${domain}','${qtype}',${rtype},'${rcode}',${ipordata});"
            ret+=$'\n'
        fi
    done
    echo "${ret}" | pcall
}
dns_nxdomain(){
    local root="${1}"
    echo "SELECT DISTINCT ON(name) name
          FROM dns_record
          WHERE qtype='A'
            AND rcode='NXDOMAIN'
            AND root='${root}'" | praw
}
dns_noerror(){
    local root="${1}"
    echo "SELECT name
          FROM dns_record
          WHERE qtype='A'
            AND rcode='NOERROR'
            AND root='${root}'
            AND ip IS NOT NULL" | praw
}
dns_ns(){
    local root="${1}"
    echo "SELECT name,data
          FROM dns_record
          WHERE root='${root}'
            AND qtype=rtype
            AND qtype='NS'" | praw
}
dns_mx(){
    local root="${1}"
    echo "SELECT name,SPLIT_PART(data,' ', 2)
    FROM dns_record
    WHERE root='${root}'
    AND qtype=rtype
    AND qtype='MX'" | praw
}
# Throw these to monitoring?
dns_cname() {
    local root="${1}"
    echo "SELECT DISTINCT ON(data) data
    FROM dns_record
    WHERE root='${root}'
    AND rtype='CNAME'" \
        | praw
}
rm_nxdomain(){
    local root="${1}"
    complement <(dns_nxdomain "${root}" | trim | uncomment) /dev/stdin
}
#------------------------------
resolved_hosts(){
    local root="${1}"
    echo "SELECT name, ip
    FROM recent_dns_record
    WHERE root='${root}'
    AND qtype='A'
    AND qtype=rtype
    AND rcode='NOERROR'
    AND ip IS NOT NULL
    GROUP BY name, ip" | praw
}
resolved_domains(){
    local root="${1}"
    echo "SELECT DISTINCT ON(name) name
    FROM recent_dns_record
    WHERE root='${root}'
    AND qtype='A'
    AND (rtype IS NULL OR qtype=rtype) -- include all noerror with empty response
    AND rcode!='NXDOMAIN'" | praw
}
resolved_ips(){
    local root="${1}"
    echo "SELECT DISTINCT ON(ip) ip
    FROM recent_dns_record
    WHERE root='${root}'
    AND qtype='A'
    AND qtype=rtype
    AND rcode='NOERROR'
    AND ip IS NOT NULL" | praw
}
#------------------------------
dns_add_wildcard(){
    local root="${1}"
    local ret=""
    while read -r subdomain ip; do
        ret+="CALL add_wildcard('${subdomain}','${root}', '${ip}');"
        ret+=$'\n'
    done
    echo "${ret}" | pcall
}
# TODO: check if domain is on subdomain of wildcard subdomains...
resolved_domains_nowildcard(){
    local root="${1}"
    echo "SELECT DISTINCT ON (reduced.name) reduced.name
    FROM (SELECT d.name, d.ip
          FROM dns_record d
          WHERE d.root='${root}'
          AND d.qtype='A'
          AND d.rcode='NOERROR') reduced
    LEFT JOIN dns_a_wildcard w
    ON  reduced.ip=w.ip
    AND reduced.name!=w.base
    AND SUBSTR(reduced.name,LENGTH(reduced.name)-LENGTH(w.base)+1)=w.base
    WHERE w.ip IS NULL" \
        | praw
}
resolved_domains_wildcard(){
    local root="${1}"
    echo "SELECT reduced.name
    FROM (SELECT d.name, d.ip
          FROM dns_record d
          WHERE d.root='${root}'
          AND d.qtype='A'
          AND d.rcode='NOERROR'
          AND d.ip IS NOT NULL) reduced
    RIGHT JOIN dns_a_wildcard w
    ON  reduced.ip=w.ip
    AND reduced.name!=w.base
    AND SUBSTR(reduced.name,LENGTH(reduced.name)-LENGTH(w.base)+1)=w.base" \
        | praw
}
rm_resolved_wildcards(){
    local root="${1}"
    complement <(resolved_domains_wildcard "${root}" | trim | uncomment) /dev/stdin
}
#------------------------------
add_ip_data(){
    local ret=""
    while IFS=, read -r ip cidr asn; do
        cidr="$(purge "${cidr}")"
        asn="$(purge "${asn}")"
        ret+="CALL insert_ip_data(INET '${ip}', CIDR ${cidr}, ${asn});"
        ret+=$'\n'
    done
    echo "${ret}" | pcall
}
# add_ip_ptr - add 1 (one) at the time
add_ip_ptr(){
    local ret=""
    while read -r rdomain rcode _ ptr; do
        ptr="$(purge "${ptr}")"
        ret+="CALL insert_ip_ptr('${rdomain}','${rcode}',${ptr});"
        ret+=$'\n'
    done
    echo "${ret}" | pcall
}
get_ip_nodata(){
    local root="${1}"
    echo "SELECT d.ip
    FROM dns_record d
    LEFT JOIN ip_data i
    ON d.ip=i.ip AND ( i.cidr IS NULL OR i.asn IS NULL)
    WHERE root='${root}'
    AND d.qtype=d.rtype
    AND d.qtype IN ('A', 'AAAA')
    AND d.ip IS NOT NULL
    GROUP BY d.ip" \
        | praw
}
get_ip_noptr(){
    local root="${1}"
    echo "SELECT DISTINCT ON (d.ip) d.ip
    FROM dns_record d
    WHERE NOT EXISTS (SELECT 1 FROM ip_ptr i WHERE d.ip=i.ip AND i.ptr IS NOT NULL)
    AND root='${root}'
    AND d.qtype=d.rtype
    AND d.qtype IN ('A', 'AAAA')" \
        | praw
}
add_ip_reverse(){
    local ret=""
    while IFS=, read -r ip reverse; do
        ret+="CALL insert_ip_reverse(INET '${ip}','${reverse}');"
        ret+=$'\n'
    done
    echo "${ret}" | pcall
}
#------------------------------
purge(){
    local s="${1}" s2=""
    until s2="${s#[[:space:]]}"; [ "$s2" = "$s" ]; do s="$s2"; done
    until s2="${s%[[:space:]]}"; [ "$s2" = "$s" ]; do s="$s2"; done
    s="${s%\"}"; s="${s#\"}"
    [[ -z ${s} ]] && echo 'NULL' || echo "'${s}'"
}

add_scan(){
    local ret=""
    while IFS=$'\t' read -r time hstatus ip host pstatus proto port service finger; do
        [[ ${hstatus} == "up" ]] && hstatus='TRUE' || hstatus='FALSE'
        service="$(purge "${service}")"
        finger="$(purge "${finger}")"
        host="$(purge "${host}")"
        ret+="CALL insert_scan(${time},${hstatus},INET '${ip}',${host}"
        if [[ -n ${pstatus} ]]; then
            ret+=",'${pstatus}','${proto}',${port},${service},${finger}"
        fi
        ret+=');'; ret+=$'\n'
    done
    echo "${ret}" | pcall
}
add_scan_file(){
    local file="${1}"
    if [[ -f ${file} ]]; then
        echo "${file}" | nthmap | add_scan
    fi
}
# No up and no local ip. No actual checking last state.
get_ips_up_clear(){
    local root="${1}"
    echo "SELECT DISTINCT ON (d.ip) d.ip
          FROM list_upips_local l
          LEFT JOIN dns_record d
            ON l.ip=d.ip
          WHERE d.root='${root}'
            AND l.ip IS NOT NULL" \
                | praw
}
get_all_down_ips(){
    echo "SELECT DISTINCT ON (ip) ip
          FROM newip_history
          WHERE is_up IS FALSE" \
              | praw
}
get_waf_ips(){
    echo "SELECT DISTINCT ON (d.ip) d.ip
          FROM ip_data d
          JOIN ip_ptr p ON d.ip=p.ip
          WHERE p.ptr LIKE '%akamaitechnologies%'
             OR p.ptr LIKE '%cloudfront.net%'
             OR d.asn IN ('Akamai',
                          'AzureFrontDoor.Frontend',
                          'CLOUDFRONT',
                          'LOCAL',
                          'DYNDNS,US',
                          'INCAPSULA,US',
                          'Cloudflare',
                          'FASTLY,US',
                          'DOSARREST,US',
                          'MICROSOFT-CORP-MSN-AS-BLOCK,US',
                          'ASN-CHEETA-MAIL,US')" | praw | sort -V
}
get_local_ips(){
    echo "SELECT DISTINCT ON (d.ip) d.ip
          FROM ip_data d
          JOIN ip_ptr p ON d.ip=p.ip
          WHERE d.asn='LOCAL'" | praw | sort -V
}
rm_local_ips(){
    complement <(get_local_ips) /dev/stdin
}
rm_waf_ips(){
    complement <(get_waf_ips) /dev/stdin
}
#
add_tld(){
    local root="${1}" # for which domain are these subdomains
    local qtype="${2}" # what record type we queried
    local ret=""
    while read -r domain rcode rtype ipordata; do
        if [[ ${qtype} == "${rtype}" ]] && [[ ${rtype} == "A" || ${rtype} == "AAAA" ]]; then
            ipordata="$(purge "${ipordata}")"
            rtype="$(purge "${rtype}")"
            ret+="CALL add_tld('${domain}','${root}','${qtype}',${rtype},'${rcode}',INET ${ipordata});"
            ret+=$'\n'
        elif [[ ${qtype} == "${rtype}" ]] && [[ ${rtype} == "SOA" ]]; then
            rtype="$(purge "${rtype}")"
            ipordata="${ipordata% * * * * *}"
            ipordata="$(purge "${ipordata}")"
            ret+="CALL add_tld('${domain}','${root}','${qtype}',${rtype},'${rcode}',${ipordata});"
            ret+=$'\n'
        else
            ipordata="$(purge "${ipordata}")"
            rtype="$(purge "${rtype}")"
            ret+="CALL add_tld('${domain}','${root}','${qtype}',${rtype},'${rcode}',${ipordata});"
            ret+=$'\n'
        fi
    done
    echo "${ret}" | pcall
}
rm_nxdomain_tlds(){
    complement <(echo "SELECT DISTINCT ON (name) name FROM tld_records WHERE rcode='NXDOMAIN'" | praw | trim | uncomment) \
               /dev/stdin
}
open_tcp_unknown(){
    local ip="${1}"
    echo "SELECT current.port
          FROM (SELECT MAX(timestamp), port, proto, pstatus
                FROM nmap_scan
                WHERE ip='${ip}'
                  AND proto='tcp'
                  AND pstatus='open'
                GROUP BY port, proto, pstatus) AS recent,
            nmap_scan AS current
          WHERE ip='${ip}'
            AND recent.port=current.port
            AND recent.max=current.timestamp
            AND recent.proto=current.proto
            AND recent.pstatus=current.pstatus
            AND finger IS NULL"\
                | praw
}

# TODO: only considers domains on dns_record, not on nmap_scan
domains_ip_port(){
    echo "SELECT webs.ip, webs.port, dns.name
          FROM (SELECT ip,host,port
                FROM nmap_scan
                WHERE proto='tcp'
                  AND pstatus='open'
                  AND finger IS NOT NULL
                  AND service IN ('http','https','ssl/http')) webs
          JOIN dns_record dns ON (dns.ip=webs.ip)
          GROUP BY webs.ip,webs.port,dns.name" \
              | praw
}
nxdomain_other(){
    echo "SELECT DISTINCT ON (name) name
          FROM dns_other
          WHERE rcode='NXDOMAIN'"\
              | praw
}
rm_nxdomain_other(){
    complement <(nxdomain_other) /dev/stdin
}
get_ips_tcp_scanned(){
    echo "SELECT DISTINCT ON (ip) ip
          FROM nmap_scan
          WHERE proto='tcp'" | praw
}
rm_ips_tcp_scanned(){
    complement <(get_ips_tcp_scanned) /dev/stdin
}
#------------------------------
# Might be throw these ones to trustrees
errors_cname(){
    echo "SELECT name,qtype
          FROM dns_record
          WHERE rcode='SERVFAIL' AND rtype='CNAME'
          GROUP BY name, qtype" | praw
}
# Throw these to subjack
errors_dangling_cname(){
    echo "SELECT data
          FROM dns_record
          WHERE rcode='NXDOMAIN' AND rtype='CNAME'" | praw
}
# TODO: needs to check for already know subdomains might be
# Things that return NOERROR, either:
# - dangling empty record
# - record with hidden subdomains
dns_weird(){
    echo "SELECT name
          FROM dns_record
          WHERE rcode='NOERROR'
            AND data IS NULL
            AND ip   IS NULL
            AND qtype='A' -- is less likely to have a missing A
          ORDER BY name ASC" | praw
}

scan_report(){
    local root="${1}"
    echo "SELECT i.asn,n.ip,d.name,n.proto,n.port,n.pstatus,n.service,n.finger,
                 CASE WHEN n.service LIKE '%https%' OR n.service LIKE 'ssl/http%' THEN 'https'
                      ELSE 'http'
                 END || '://' || d.name || CASE WHEN n.port=80  THEN ''
                                                WHEN n.port=443 THEN ''
                                                ELSE ':' || n.port::TEXT END || '/'
          FROM nmap_scan n
          JOIN      dns_record     d ON d.ip=n.ip AND n.pstatus='open'
          JOIN      ip_data        i ON i.ip=d.ip
          LEFT JOIN dns_a_wildcard w ON d.ip=w.ip
          WHERE d.root='${root}'
            AND (w.ip IS NULL OR w.base=d.name)
          GROUP BY i.asn,n.ip,d.name,n.proto,n.port,n.pstatus,n.service,n.finger
          ORDER BY d.name,n.ip" | praw
}

scan_report_waf(){
    local root="${1}"
    echo "SELECT i.asn,n.ip,d.name,n.proto,n.port,n.pstatus,n.service,n.finger,
                 CASE WHEN n.service LIKE '%https%' OR n.service LIKE 'ssl/http%' THEN 'https'
                      ELSE 'http'
                 END || '://' || d.name || CASE WHEN n.port=80  THEN ''
                                                WHEN n.port=443 THEN ''
                                                ELSE ':' || n.port::TEXT END || '/'
          FROM nmap_scan n
          JOIN      dns_record     d ON d.ip=n.ip AND n.pstatus='open'
          JOIN      ip_data        i ON i.ip=d.ip
          LEFT JOIN dns_a_wildcard w ON d.ip=w.ip
          WHERE d.root='${root}'
            AND (w.ip IS NULL OR w.base=d.name)
            AND i.asn IN ('Akamai',
                          'AzureFrontDoor.Frontend',
                          'CLOUDFRONT',
                          'DYNDNS,US',
                          'INCAPSULA,US',
                          'Cloudflare',
                          'FASTLY,US',
                          'DOSARREST,US',
                          'MICROSOFT-CORP-MSN-AS-BLOCK,US',
                          'ASN-CHEETA-MAIL,US')
          GROUP BY i.asn,n.ip,d.name,n.proto,n.port,n.pstatus,n.service,n.finger
          ORDER BY d.name,n.ip" | praw
}

scan_report_no_waf(){
    local root="${1}"
    echo "SELECT i.asn,n.ip,d.name,n.proto,n.port,n.pstatus,n.service,n.finger,
                 CASE WHEN n.service LIKE '%https%' OR n.service LIKE 'ssl/http%' THEN 'https'
                      ELSE 'http'
                 END || '://' || d.name || CASE WHEN n.port=80  THEN ''
                                                WHEN n.port=443 THEN ''
                                                ELSE ':' || n.port::TEXT END || '/'
          FROM      nmap_scan      n
          JOIN      dns_record     d ON d.ip=n.ip AND n.pstatus='open'
          JOIN      ip_data        i ON i.ip=d.ip
          LEFT JOIN dns_a_wildcard w ON d.ip=w.ip
          WHERE d.root='${root}'
            AND (w.ip IS NULL OR w.base=d.name)
            AND i.asn NOT IN ('Akamai',
                              'AzureFrontDoor.Frontend',
                              'CLOUDFRONT',
                              'LOCAL',
                              'DYNDNS,US',
                              'INCAPSULA,US',
                              'Cloudflare',
                              'FASTLY,US',
                              'DOSARREST,US',
                              'MICROSOFT-CORP-MSN-AS-BLOCK,US',
                              'ASN-CHEETA-MAIL,US')
          GROUP BY i.asn,n.ip,d.name,n.proto,n.port,n.pstatus,n.service,n.finger
          ORDER BY d.name,n.ip" | praw
}

#------------------------------
http_report(){
    echo "SELECT i.asn,
                 ROUND(h.length/1024.0/1024.0,4) as mbytes,
                 h.qheaders->>'Host' as rhost,
                 h.host,h.status,h.method,h.path
          FROM http_entries h
          LEFT JOIN ip_data i ON host(i.ip)=h.host
          WHERE h.length!=23 and h.status=200
          GROUP BY i.asn,rhost,h.host,h.status,h.method,h.path,h.length
          ORDER BY rhost" | praw
}

#------------------------------

iwp(){
    echo "SELECT ip FROM ip_data WHERE asn IS NOT NULL" | praw
}
rm_ips_with_provider(){
    complement <(iwp) /dev/stdin
}

