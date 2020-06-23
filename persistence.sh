#!/bin/bash

# TODO: IPs might be should be global (not per schema)
# TODO: save subdomain, domain and SLD+TLD separate
set -xu

IP_HISTORY='ip_history'
IP_DATA='ip_data'

cleardb(){
    echo "
DROP TABLE IF EXISTS dns_a_wildcard;
DROP TABLE IF EXISTS dns_record;
DROP TABLE IF EXISTS ip_ptr;
DROP TABLE IF EXISTS ${IP_DATA};
DROP TABLE IF EXISTS ${IP_HISTORY};
" | psql -U postgres
}
initdb(){
    template="""
CREATE TABLE IF NOT EXISTS dns_a_wildcard(
    base      VARCHAR(256) NOT NULL,
    root      VARCHAR(256) NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET);
CREATE TABLE IF NOT EXISTS dns_record(
    name      VARCHAR(256) NOT NULL,
    root      VARCHAR(256) NOT NULL,
    sub       VARCHAR(256) NOT NULL,
    timestamp TIMESTAMP    DEFAULT NOW(),
    qtype     VARCHAR(16)  NOT NULL,
    rtype     VARCHAR(16),
    rcode     VARCHAR(16)  NOT NULL,
    data      VARCHAR(512),
    ip        INET);
CREATE TABLE IF NOT EXISTS ip_ptr (
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET NOT NULL,
    ptr       VARCHAR(256)
);
CREATE TABLE IF NOT EXISTS ${IP_DATA}(
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET NOT NULL,
    cidr      CIDR,
    asn       VARCHAR(256));
CREATE TABLE IF NOT EXISTS ${IP_HISTORY}(
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET NOT NULL,
    is_up     BOOLEAN);
--------------------
DROP PROCEDURE IF EXISTS insert_ip_ptr;
CREATE PROCEDURE insert_ip_ptr(newip  INET,
                               newptr VARCHAR)
LANGUAGE SQL
AS \$$
INSERT INTO ip_ptr(ip, ptr)
SELECT newip, newptr
WHERE NOT EXISTS (
    SELECT 1
    FROM (
        SELECT ip, max(timestamp) as maxtime
        FROM ip_ptr
        WHERE ip=newip
        GROUP BY ip
    ) recent,
    ip_ptr original
    WHERE original.ip=recent.ip
    AND recent.maxtime=original.timestamp
    AND original.ptr!=newptr);
\$$;
--------------------
DROP PROCEDURE IF EXISTS insert_ip_data;
CREATE PROCEDURE insert_ip_data(newip   INET,
                                newcidr CIDR,
                                newasn  VARCHAR)
LANGUAGE SQL
AS \$$
INSERT INTO ${IP_DATA}(ip, cidr, asn)
SELECT newip, newcidr, newasn
WHERE NOT EXISTS (
    SELECT 1
    FROM (
        SELECT ip, max(timestamp) as maxtime
        FROM ${IP_DATA}
        WHERE ip=newip
        GROUP BY ip
    ) recent,
    ${IP_DATA} original
    WHERE original.ip=recent.ip
    AND recent.maxtime=original.timestamp
    AND ( original.cidr!=newcidr
          OR original.asn!=newasn));
\$$;
--------------------
DROP PROCEDURE IF EXISTS add_wildcard;
CREATE PROCEDURE add_wildcard(newbase VARCHAR,
                              newroot VARCHAR,
                              newip   INET)
LANGUAGE SQL
AS \$$
INSERT INTO dns_a_wildcard(base, root, ip)
SELECT LOWER(newbase), LOWER(newroot), newip
WHERE NOT EXISTS (
    SELECT 1
    FROM dns_a_wildcard
    WHERE base=newbase
    AND root=newroot
    AND ip=newip);
\$$;
--------------------
DROP PROCEDURE IF EXISTS add_dns(varchar,varchar,varchar,varchar,varchar,varchar);
CREATE PROCEDURE add_dns(newdomain VARCHAR,
                         newroot   VARCHAR,
                         newqtype  VARCHAR,
                         newrtype  VARCHAR,
                         newrcode  VARCHAR,
                         newdata   VARCHAR)
LANGUAGE SQL
AS \$$
INSERT INTO dns_record(name, root, sub, qtype, rtype, rcode, data)
SELECT LOWER(newdomain),
       LOWER(newroot),
       CASE
         WHEN LOWER(newdomain)=LOWER(newroot) THEN LOWER(newdomain)
         ELSE SUBSTR(LOWER(newdomain),1,LENGTH(newdomain)-LENGTH(newroot)-1)
       END,
       UPPER(newqtype),
       newrtype,
       newrcode,
       newdata
WHERE NOT EXISTS (
    SELECT 1
    FROM dns_record
    WHERE name=newdomain
    AND root=newroot
    AND rcode=newrcode
    AND data=newdata);
\$$;
DROP PROCEDURE IF EXISTS add_dns(varchar,varchar,varchar,varchar,varchar,inet);
CREATE PROCEDURE add_dns(newdomain VARCHAR,
                         newroot   VARCHAR,
                         newqtype  VARCHAR,
                         newrtype  VARCHAR,
                         newrcode  VARCHAR,
                         newip     INET)
LANGUAGE SQL
AS \$$
INSERT INTO dns_record(name, root, sub, qtype, rtype, rcode, ip)
SELECT LOWER(newdomain),
       LOWER(newroot),
       CASE
         WHEN LOWER(newdomain)=LOWER(newroot) THEN LOWER(newdomain)
         ELSE SUBSTR(LOWER(newdomain),1,LENGTH(newdomain)-LENGTH(newroot)-1)
       END,
       UPPER(newqtype),
       newrtype,
       newrcode,
       newip
WHERE NOT EXISTS (
    SELECT 1
    FROM dns_record
    WHERE name=newdomain
    AND root=newroot
    AND rcode=newrcode
    AND ip=newip);
\$$;
--------------------
DROP PROCEDURE IF EXISTS insert_ip;
CREATE PROCEDURE insert_ip(newip INET)
LANGUAGE SQL
AS \$$
INSERT INTO ${IP_HISTORY}(ip)
SELECT newip
WHERE NOT EXISTS (
    SELECT 1
    FROM ${IP_HISTORY}
    WHERE ip=newip);
\$$;
--------------------
DROP PROCEDURE IF EXISTS insert_upip;
CREATE PROCEDURE insert_upip(newip INET)
LANGUAGE SQL
AS \$$
INSERT INTO ${IP_HISTORY}(ip,is_up)
SELECT newip, true
WHERE NOT EXISTS (
    SELECT 1
    FROM (
        SELECT ip, max(timestamp) as maxtime
        FROM ${IP_HISTORY}
        WHERE ip=newip
        GROUP BY ip
    ) recent,
    ${IP_HISTORY} original
    WHERE original.ip=recent.ip
    AND recent.maxtime=original.timestamp
    AND original.is_up=true);
\$$;
DROP PROCEDURE IF EXISTS insert_downip;
CREATE PROCEDURE insert_downip(newip INET)
LANGUAGE SQL
AS \$$
INSERT INTO ${IP_HISTORY}(ip,is_up)
SELECT newip, false
WHERE NOT EXISTS (
    SELECT 1
    FROM (
        SELECT ip, max(timestamp) as maxtime
        FROM ${IP_HISTORY}
        WHERE ip=newip
        GROUP BY ip
    ) recent,
    ${IP_HISTORY} original
    WHERE original.ip=recent.ip
    AND recent.maxtime=original.timestamp
    AND original.is_up=false);
\$$;
"""
    echo "${template}" | psql -U postgres
}
#------------------------------
add_ips() {
    local ret=""
    while read -r ip; do ret+="CALL insert_ip('${ip}');"; done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
add_ips_up() {
    local ret=""
    while read -r ip; do ret+="CALL insert_upip('${ip}');"; done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
add_ips_down() {
    local ret=""
    while read -r ip; do ret+="CALL insert_downip('${ip}');"; done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
get_ips_up(){
    local root="${1}"
    echo "SELECT recent.ip FROM (
  SELECT ${IP_HISTORY}.ip, max(${IP_HISTORY}.timestamp) as mtime
  FROM ${IP_HISTORY}
  INNER JOIN dns_record ON (${IP_HISTORY}.ip=dns_record.ip)
  WHERE dns_record.root='${root}'
  GROUP BY ${IP_HISTORY}.ip) recent,
  ${IP_HISTORY} original
WHERE original.timestamp=recent.mtime
  AND original.ip=recent.ip
  AND original.is_up=true;
" | psql -U postgres -t -A
}
get_ips_down(){
    local root="${1}"
    echo "SELECT recent.ip FROM (
  SELECT ${IP_HISTORY}.ip, max(${IP_HISTORY}.timestamp) as mtime
  FROM ${IP_HISTORY}
  INNER JOIN dns_record ON (${IP_HISTORY}.ip=dns_record.ip)
  WHERE dns_record.root='${root}'
  GROUP BY ${IP_HISTORY}.ip) recent,
  ${IP_HISTORY} original
WHERE original.timestamp=recent.mtime
  AND original.ip=recent.ip
  AND original.is_up=false;
" | psql -U postgres -t -A
}
get_ips_unknown(){
    local root="${1}"
    echo "SELECT recent.ip FROM (
  SELECT ${IP_HISTORY}.ip, max(${IP_HISTORY}.timestamp) as mtime
  FROM ${IP_HISTORY}
  INNER JOIN dns_record ON (${IP_HISTORY}.ip=dns_record.ip)
  WHERE dns_record.root='${root}'
  GROUP BY ${IP_HISTORY}.ip) recent,
  ${IP_HISTORY} original
WHERE original.timestamp=recent.mtime
  AND original.ip=recent.ip
  AND original.is_up IS NULL;
" | psql -U postgres -t -A
}
get_subs(){
    echo "SELECT DISTINCT ON (sub) sub FROM dns_record" | psql -U postgres -t -A
}
#------------------------------
add_dns(){
    local root="${1}" # for which domain are these subdomains
    local qtype="${2}" # what record type we queried
    local ret=""
    while read -r domain rcode rtype ipordata; do
        if [[ ${qtype} == "${rtype}" ]] && [[ ${rtype} == "A" || ${rtype} == "AAAA" ]]; then
            [[ -z ${ipordata} ]] && ipordata=NULL || ipordata="'${ipordata}'"
            [[ -z ${rtype}    ]] && rtype=NULL    || rtype="'${rtype}'"
            ret+="CALL add_dns('${domain}','${root}','${qtype}',${rtype},'${rcode}',INET ${ipordata});
"
        else
            [[ -z ${ipordata} ]] && ipordata=NULL || ipordata="'${ipordata}'"
            [[ -z ${rtype}    ]] && rtype=NULL    || rtype="'${rtype}'"

            ret+="CALL add_dns('${domain}','${root}','${qtype}',${rtype},'${rcode}',${ipordata});
"
        fi
    done
    echo -n "${ret}" | psql -U postgres | grep -c CALL || true
}
dns_nxdomain(){
    local root="${1}"
    echo "SELECT name
          FROM dns_record
          WHERE qtype='A'
            AND rcode='NXDOMAIN'
            AND root='${root}'" | psql -U postgres -t -A
}
dns_noerror(){
    local root="${1}"
    echo "SELECT name
          FROM dns_record
          WHERE qtype='A'
            AND rcode='NOERROR'
            AND root='${root}'
            AND ip IS NOT NULL" | psql -U postgres -t -A
}
dns_ns(){
    local root="${1}"
    echo "SELECT name,data
          FROM dns_record
          WHERE root='${root}'
            AND qtype=rtype
            AND qtype='NS'" | psql -U postgres -t -A
}
dns_mx(){
    local root="${1}"
    echo "SELECT name,SPLIT_PART(data,' ', 2)
          FROM dns_record
          WHERE root='${root}'
            AND qtype=rtype
            AND qtype='MX'" | psql -U postgres -t -A
}
dns_cname() {
    local root="${1}"
    echo "SELECT data
          FROM dns_record
          WHERE root='${root}'
            AND rtype='CNAME'
          GROUP BY data" | psql -U postgres -t -A
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
            AND qtype='A'
          ORDER BY name ASC;" | psql -U postgres -t -A
}
rm_nxdomain(){
    local root="${1}"
    grep -F -v -f <(dns_nxdomain "${root}" | trim | uncomment) < /dev/stdin
}
#------------------------------
resolved_hosts(){
    local root="${1}"
    echo "SELECT name, ip
          FROM dns_record
          WHERE qtype='A'
            AND qtype=rtype
            AND root='${root}'
            AND rcode='NOERROR'
            AND ip IS NOT NULL
          GROUP BY name, ip" | psql -U postgres -t -A
}
resolved_domains(){
    local root="${1}"
    echo "SELECT name
          FROM dns_record
          WHERE qtype='A'
            AND qtype=rtype
            AND root='${root}'
            AND rcode='NOERROR'
            AND ip IS NOT NULL
          GROUP BY name" | psql -U postgres -t -A
}
resolved_ips(){
    local root="${1}"
    echo "SELECT ip
          FROM dns_record
          WHERE qtype='A'
            AND qtype=rtype
            AND root='${root}'
            AND rcode='NOERROR'
            AND ip IS NOT NULL
          GROUP BY ip" | psql -U postgres -t -A
}
#------------------------------
dns_add_wildcard(){
    local root="${1}"
    local ret=""
    while read -r subdomain ip; do
        ret+="CALL add_wildcard('${subdomain}','${root}', '${ip}');"
        ret+=$'\n'
    done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
# TODO: check if domain is on subdomain of wildcard subdomains...
resolved_domains_nowildcard(){
    local root="${1}"
    echo "SELECT reduced.name
          FROM (SELECT d.name, d.ip
                FROM dns_record d
                WHERE d.root='${root}'
                  AND d.qtype='A'
                  AND d.rcode='NOERROR'
                  AND d.ip IS NOT NULL) reduced
          LEFT JOIN dns_a_wildcard w
              ON  reduced.ip=w.ip
              AND reduced.name!=w.base
              AND SUBSTR(reduced.name,LENGTH(reduced.name)-LENGTH(w.base)+1)=w.base
          WHERE w.ip IS NULL
" | psql -U postgres -t -A
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
                  | psql -U postgres -t -A
}
rm_resolved_wildcards(){
    local root="${1}"
    grep -F -v -f <(resolved_domains_wildcard "${root}"|trim|uncomment) \
         < /dev/stdin
}
#------------------------------
add_ip_data(){
    local ret=""
    while IFS=, read -r ip cidr asn; do
        [[ -z ${cidr} ]] && cidr='NULL' || cidr="CIDR '${cidr}'"
        [[ -z ${asn}  ]] && asn='NULL'  || asn="'${asn}'"
        ret+="CALL insert_ip_data(INET '${ip}', ${cidr}, ${asn});"
        ret+=$'\n'
    done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
# add_ip_ptr - add 1 (one) at the time
add_ip_ptr(){
    local ip="${1}" ptr="${2}"
    [[ -z ${ptr} ]] && ptr='NULL' || ptr="'${ptr}'"
    echo "CALL insert_ip_ptr('${ip}',${ptr});"\
        | psql -U postgres | grep -c CALL || true
}
get_ip_nodata(){
    local root="${1}"
    echo "SELECT d.ip
          FROM dns_record d
          LEFT JOIN ${IP_DATA} i
            ON d.ip=i.ip AND ( i.cidr IS NULL OR i.asn IS NULL)
          WHERE root='${root}'
            AND d.qtype=d.rtype
            AND d.qtype IN ('A', 'AAAA')
            AND d.ip IS NOT NULL
          GROUP BY d.ip" \
              | psql -U postgres -t -A
}
get_ip_noptr(){
    local root="${1}"
    echo "SELECT d.ip
          FROM dns_record d
          LEFT JOIN ip_ptr i
            ON d.ip=i.ip AND i.ptr IS NULL
          WHERE root='${root}'
            AND d.qtype=d.rtype
            AND d.qtype IN ('A', 'AAAA')
            AND d.ip IS NOT NULL
          GROUP BY d.ip" \
              | psql -U postgres -t -A
}
