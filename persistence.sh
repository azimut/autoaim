#!/bin/bash

# TODO: IPs might be should be global (not per schema)
# TODO: save subdomain, domain and SLD+TLD separate
# TODO: add name resolve queries of NS MX to dns_rec
# TODO: rm downip and upip in favor of insert_ip(ip,status)
set -xu

IP_HISTORY='ip_history'
IP_DATA='ip_data'

# cleardb(){
#     echo "
# DROP TABLE IF EXISTS nmap_scan;
# DROP TABLE IF EXISTS dns_a_wildcard;
# DROP TABLE IF EXISTS dns_record;
# DROP TABLE IF EXISTS ip_ptr;
# DROP TABLE IF EXISTS ${IP_DATA};
# DROP TABLE IF EXISTS ${IP_HISTORY};
# " | psql -U postgres
# }
initdb(){
    template="""
-- dns_record but latest results
CREATE OR REPLACE VIEW recent_dns_record AS
  SELECT current.*
  FROM (SELECT name,qtype,MAX(timestamp) AS maximun FROM dns_record GROUP BY name,qtype) recent
  JOIN dns_record current
  ON current.timestamp=recent.maximun AND current.name=recent.name AND current.qtype=recent.qtype;

-- IPs currently UP
CREATE OR REPLACE VIEW newip_history AS
  SELECT recent.maximo AS timestamp, recent.ip, current.is_up
  FROM (SELECT ip,MAX(timestamp) maximo FROM ip_history GROUP BY ip) recent
  JOIN ip_history current
  ON (recent.ip=current.ip AND current.timestamp=recent.maximo);

CREATE OR REPLACE VIEW list_upips AS
  SELECT DISTINCT ON (current.ip) current.ip
   FROM ( SELECT ip_history.ip,
            max(ip_history.timestamp) AS maximus
           FROM ip_history
          GROUP BY ip_history.ip) recent,
    ip_history current
  WHERE current.ip = recent.ip AND current.timestamp = recent.maximus AND current.is_up IS TRUE;

CREATE OR REPLACE VIEW list_upips_local AS
  SELECT d.ip
   FROM list_upips i
     JOIN ip_data d ON i.ip = d.ip AND (d.asn IS NULL OR d.asn::text <> 'LOCAL'::text);

CREATE TABLE IF NOT EXISTS nmap_scan(
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET NOT NULL,
    host      VARCHAR(256),
    pstatus   VARCHAR(8),
    proto     VARCHAR(8),
    port      INTEGER,
    service   VARCHAR(32),
    finger    VARCHAR(32)
);
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
    timestamp TIMESTAMP   DEFAULT NOW(),
    ip        INET        NOT NULL,
    rcode     VARCHAR(16) NOT NULL,
    ptr       VARCHAR(256)
);
CREATE TABLE IF NOT EXISTS ip_reverse (
    ip        INET         NOT NULL PRIMARY KEY,
    reverse   VARCHAR(256) NOT NULL
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
------------------------------
DROP PROCEDURE IF EXISTS insert_ip_reverse;
CREATE PROCEDURE insert_ip_reverse(newip     INET,
                                  newreverse VARCHAR)
LANGUAGE SQL
AS \$$
INSERT INTO ip_reverse(ip, reverse)
SELECT newip, newreverse
WHERE NOT EXISTS (
    SELECT 1
    FROM ip_reverse
    WHERE ip=newip);
\$$;
--------------------
DROP PROCEDURE IF EXISTS insert_ip_ptr;
CREATE PROCEDURE insert_ip_ptr(newrdomain VARCHAR,
                               newrcode   VARCHAR,
                               newptr     VARCHAR)
LANGUAGE SQL
AS \$$
INSERT INTO ip_ptr(ip, rcode, ptr)
SELECT rv.ip, newrcode, newptr
FROM ip_reverse rv
WHERE rv.reverse=newrdomain
AND NOT EXISTS (
    SELECT 1
    FROM (
        SELECT ip, max(timestamp) as maxtime
        FROM ip_ptr
        WHERE ip=rv.ip
        GROUP BY ip
    ) recent,
    ip_ptr original
    WHERE original.ip=recent.ip
      AND original.timestamp=recent.maxtime
      AND ( original.ptr=newptr OR ( original.ptr IS NULL AND newptr IS NULL) )
      AND original.rcode=newrcode);
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
      AND ( ( original.cidr=newcidr AND original.asn=newasn) OR
            ( original.cidr IS NULL AND newcidr IS NULL)));
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
    AND ((data IS NULL AND newdata IS NULL) OR data=newdata));
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
    AND ((ip IS NULL AND newip IS NULL) OR ip=newip));
\$$;
--------------------
DROP PROCEDURE IF EXISTS insert_ip(inet, boolean, timestamp);
DROP PROCEDURE IF EXISTS insert_ip(inet, boolean);
DROP PROCEDURE IF EXISTS insert_ip(inet);
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
CREATE PROCEDURE insert_ip(newip INET, state BOOLEAN)
LANGUAGE SQL
AS \$$
INSERT INTO ${IP_HISTORY}(ip,is_up)
SELECT newip, state
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
    AND original.is_up=state);
\$$;
CREATE PROCEDURE insert_ip(newip INET, state BOOLEAN, newtime TIMESTAMP WITH TIME ZONE)
LANGUAGE SQL
AS \$$
INSERT INTO ${IP_HISTORY}(ip,is_up,timestamp)
SELECT newip, state, newtime
WHERE NOT EXISTS (
    SELECT 1
    FROM ${IP_HISTORY}
    WHERE ip=newip
      AND timestamp=newtime
      AND is_up=state);
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
------------------------------
-- # time hstatus ip host pstatus proto port service finger
DROP PROCEDURE IF EXISTS insert_scan(integer,boolean,inet,varchar,varchar,varchar,integer,varchar,varchar);
CREATE PROCEDURE insert_scan(newtimestamp  INTEGER,
                             newhstatus    BOOLEAN,
                             newip         INET,
                             newhost       VARCHAR,
                             newpstatus    VARCHAR,
                             newproto      VARCHAR,
                             newport       INTEGER,
                             newservice    VARCHAR,
                             newfinger     VARCHAR)
LANGUAGE SQL
AS \$$
CALL insert_ip(newip, newhstatus, TO_TIMESTAMP(newtimestamp));
INSERT INTO nmap_scan(timestamp, ip, host,
                      pstatus, proto, port, service, finger)
SELECT TO_TIMESTAMP(newtimestamp), newip, newhost,
      newpstatus, newproto, newport, newservice, newfinger
WHERE NOT EXISTS (
    SELECT 1
    FROM (
      SELECT ip, max(timestamp) as maxtime
      FROM nmap_scan
      WHERE ip=newip
        AND (host=newhost OR (host IS NULL AND newhost IS NULL))
        AND port=newport
      GROUP BY ip) recent,
    nmap_scan original
    WHERE original.ip=recent.ip AND original.timestamp=recent.maxtime
      AND pstatus=newpstatus
      AND proto=newproto
      AND port=newport
      AND ((host    IS NULL AND newhost    IS NULL) OR host=newhost)
      AND ((service IS NULL AND newservice IS NULL) OR service=newservice)
      AND ((finger  IS NULL AND newfinger  IS NULL) OR finger=newfinger));
\$$;
DROP PROCEDURE IF EXISTS insert_scan(integer,boolean,inet,varchar);
CREATE PROCEDURE insert_scan(newtimestamp INTEGER,
                             newhstatus   BOOLEAN,
                             newip        INET,
                             newhost      VARCHAR)
LANGUAGE SQL
AS \$$
CALL insert_ip(newip, newhstatus, TO_TIMESTAMP(newtimestamp));
INSERT INTO nmap_scan(timestamp, ip, host)
SELECT TO_TIMESTAMP(newtimestamp), newip, newhost
WHERE NOT EXISTS (
    SELECT 1
    FROM (
      SELECT ip, max(timestamp) as maxtime
      FROM nmap_scan
      WHERE ip=newip
        AND (host=newhost OR (host IS NULL AND newhost IS NULL))
      GROUP BY ip) recent,
    nmap_scan original
    WHERE original.ip=recent.ip
      AND original.timestamp=recent.maxtime
      AND ((host IS NULL AND newhost IS NULL) OR host=newhost));
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
    complement <(dns_nxdomain "${root}") /dev/stdin
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
    echo "SELECT DISTINCT ON(name) name
          FROM dns_record
          WHERE qtype='A'
            AND qtype=rtype
            AND root='${root}'
            AND (rcode NOT IN ('NOERROR','NXDOMAIN') OR (rcode='NOERROR' AND ip IS NOT NULL))" | psql -U postgres -t -A | trim | uncomment
}
resolved_ips(){
    local root="${1}"
    echo "SELECT DISTINCT ON(ip) ip
          FROM dns_record
          WHERE qtype='A'
            AND qtype=rtype
            AND root='${root}'
            AND rcode='NOERROR'
            AND ip IS NOT NULL" | psql -U postgres -t -A | trim | uncomment
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
    echo "SELECT DISTINCT ON (reduced.name) reduced.name
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
" | psql -U postgres -t -A | trim | uncomment
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
                  | psql -U postgres -t -A | trim | uncomment
}
rm_resolved_wildcards(){
    local root="${1}"
    complement <(resolved_domains_wildcard "${root}") /dev/stdin
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
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
# add_ip_ptr - add 1 (one) at the time
add_ip_ptr(){
    local ret=""
    while read -r rdomain rcode _ ptr; do
        ptr="$(purge "${ptr}")"
        ret+="CALL insert_ip_ptr('${rdomain}','${rcode}',${ptr});"
        ret+=$'\n'
    done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
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
    echo "SELECT DISTINCT ON (d.ip) d.ip
          FROM dns_record d
          WHERE NOT EXISTS (SELECT 1 FROM ip_ptr i WHERE d.ip=i.ip AND i.ptr IS NOT NULL)
          AND root='${root}'
            AND d.qtype=d.rtype
            AND d.qtype IN ('A', 'AAAA')" \
                | psql -U postgres -t -A
}
add_ip_reverse(){
    local ret=""
    while IFS=, read -r ip reverse; do
        ret+="CALL insert_ip_reverse(INET '${ip}','${reverse}');"
        ret+=$'\n'
    done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
#------------------------------
purge(){
    local s="${1}" s2=""
    until s2="${s#[[:space:]]}"; [ "$s2" = "$s" ]; do s="$s2"; done
    until s2="${s%[[:space:]]}"; [ "$s2" = "$s" ]; do s="$s2"; done
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
    echo "${ret}" | psql -U postgres -t -A | grep -F -c CALL || true
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
                | psql -U postgres -At
}
get_all_down_ips(){
    echo "SELECT DISTINCT ON (ip) ip
          FROM newip_history
          WHERE is_up IS FALSE" \
              | psql -U postgres -t -A
}
