#!/bin/bash

# TODO: IPs might be should be global (not per schema)
# TODO: save subdomain, domain and SLD+TLD separate
set -xu

IP_HISTORY='ip_history'
IP_DATA='ip_data'

parse(){
    local domain="${1}"
    domain="${domain//./_}"
    echo "${domain}"
}

cleardb(){
    echo "
DROP TABLE IF EXISTS dns_a_wildcard;
DROP TABLE IF EXISTS dns_a;
DROP TABLE IF EXISTS ${IP_DATA};
DROP TABLE IF EXISTS ${IP_HISTORY};
DROP PROCEDURE IF EXISTS add_wildcard;
DROP PROCEDURE IF EXISTS get_ips_up;
DROP PROCEDURE IF EXISTS add_dns_a;
DROP PROCEDURE IF EXISTS insert_ip;
DROP PROCEDURE IF EXISTS insert_upip;
DROP PROCEDURE IF EXISTS insert_downip;
" | psql -U postgres
}

initdb(){
    template="""
CREATE TABLE IF NOT EXISTS dns_a_wildcard(
    base      VARCHAR(256) NOT NULL,
    root      VARCHAR(256) NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET
);
CREATE TABLE IF NOT EXISTS dns_a(
    name      VARCHAR(256) NOT NULL,
    root      VARCHAR(256) NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    rcode     VARCHAR(32) NOT NULL,
    ip        INET
);

CREATE TABLE IF NOT EXISTS ${IP_DATA}(
    ip   INET PRIMARY KEY NOT NULL,
    cidr CIDR,
    asn  VARCHAR(256)
);
CREATE TABLE IF NOT EXISTS ${IP_HISTORY}(
    ip        INET NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    is_up     BOOLEAN
);

--------------------
CREATE PROCEDURE add_wildcard(newbase varchar(256),
                              newroot varchar(256),
                              newip   inet)
LANGUAGE SQL
AS \$$
INSERT INTO dns_a_wildcard(base, root, ip)
  SELECT newbase, newroot, newip
  WHERE NOT EXISTS (
    SELECT 1
    FROM dns_a_wildcard
    WHERE base=newbase
      AND root=newroot
      AND ip=newip);
\$$;
--------------------
CREATE PROCEDURE get_ips_up()
LANGUAGE SQL
AS \$$
SELECT recent.ip FROM (
  SELECT ip, max(timestamp) as mtime
  FROM ${IP_HISTORY}
  GROUP BY ip) recent,
  ${IP_HISTORY} original
WHERE original.timestamp=recent.mtime
  AND original.ip=recent.ip
  AND original.is_up=true;
\$$;
--------------------
CREATE PROCEDURE add_dns_a(newdomain varchar(256),
                           newroot   varchar(256),
                           newrcode  varchar(32),
                           newip     inet)
LANGUAGE SQL
AS \$$
INSERT INTO dns_a(name, root, rcode, ip)
SELECT newdomain, newroot,  newrcode, newip
WHERE NOT EXISTS (
    SELECT 1
    FROM dns_a
    WHERE name=newdomain
    AND root=newroot
    AND rcode=newrcode
    AND ip=newip);
\$$;
--------------------
CREATE PROCEDURE insert_ip(newip inet)
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
CREATE PROCEDURE insert_upip(newip inet)
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
CREATE PROCEDURE insert_downip(newip inet)
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
    while read -r ip; do ret+="CALL insert_downip('${ip}');"; done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
add_ips_down() {
    local ret=""
    while read -r ip; do ret+="CALL insert_downip('${ip}');"; done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
get_ips_up(){
    local root="${1}"
    echo "CALL get_ips();" | psql -U postgres | grep -c CALL || true
}
#------------------------------
add_dns_a(){
    local root="${1}"
    local ret=""
    while read -r domain rcode ip; do
        if [[ -z ${ip} ]]; then
            ret+="CALL add_dns_a('${domain}','${root}','${rcode}',NULL);"
        else
            ret+="CALL add_dns_a('${domain}','${root}','${rcode}','${ip}');"
        fi
    done
    echo -n "${ret}" | psql -U postgres | grep -c CALL || true
}
dns_nxdomain(){
    local root="${1}"
    echo "SELECT name FROM dns_a
    WHERE rcode='NXDOMAIN' AND root='${root}'" | psql -U postgres -t -A
}

dns_noerror(){
    local root="${1}"
    echo "SELECT name FROM dns_a
    WHERE rcode='NOERROR' AND root='${root}'" | psql -U postgres -t -A
}

rm_nxdomain(){
    local root="${1}"
    grep -v -f <(dns_nxdomain "${root}") < /dev/stdin
}
#------------------------------
resolved_hosts(){
    local root="${1}"
    echo "SELECT name, ip
          FROM dns_a
          WHERE root='${root}' AND rcode='NOERROR'
          GROUP BY name, ip" | psql -U postgres -t -A
}
resolved_domains(){
    local root="${1}"
    echo "SELECT name
          FROM dns_a
          WHERE root='${root}' AND rcode='NOERROR'
          GROUP BY name" | psql -U postgres -t -A
}

resolved_ips(){
    local root="${1}"
    echo "SELECT ip
          FROM dns_a
          WHERE root='${root}' AND rcode='NOERROR'
          GROUP BY ip" | psql -U postgres -t -A
}
#------------------------------
dns_add_wildcard(){
    local root="${1}"
    local ret=""
    while read -r subdomain ip; do
        ret+="CALL add_wildcard('${subdomain}','${root}', '${ip}');
"
    done
    echo "${ret}" | psql -U postgres | grep -c CALL || true
}
resolved_domains_nowildcard(){
    local root="${1}"
    echo "SELECT d.name
          FROM dns_a d, dns_a_wildcard w
          WHERE d.root='${root}' AND w.root='${root}' AND d.ip!=w.ip
          GROUP BY d.name" | psql -U postgres -t -A
}
