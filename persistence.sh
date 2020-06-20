#!/bin/bash

# TODO: IPs might be should be global (not per schema)

set -xu

IP_HISTORY='ip_history'
IP_DATA='ip_data'

cleardb(){
    local dbname
    dbname="$(parse ${1})"
    echo "DROP SCHEMA ${dbname} CASCADE" | psql -U postgres
}

initdb(){
    local dbname
    dbname="$(parse ${1})"
    template="""
CREATE SCHEMA IF NOT EXISTS ${dbname};

CREATE TABLE IF NOT EXISTS ${dbname}.dns_a(
    name      VARCHAR(256) NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    rcode     VARCHAR(32),
    ip        INET NOT NULL
);
CREATE TABLE IF NOT EXISTS ${dbname}.${IP_DATA}(
    ip   INET PRIMARY KEY NOT NULL,
    cidr CIDR,
    asn  VARCHAR(256)
);
CREATE TABLE IF NOT EXISTS ${dbname}.${IP_HISTORY}(
    ip        INET NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    is_up     BOOLEAN
);
--------------------
DROP PROCEDURE IF EXISTS get_ips_up;
CREATE PROCEDURE get_ips_up()
LANGUAGE SQL
AS \$$
SELECT recent.ip FROM (
  SELECT ip, max(timestamp) as mtime
  FROM ${dbname}.${IP_HISTORY}
  GROUP BY ip) recent,
  ${dbname}.${IP_HISTORY} original
WHERE original.timestamp=recent.mtime
  AND original.ip=recent.ip
  AND original.is_up=true;
\$$;

DROP PROCEDURE IF EXISTS add_dns_a;
CREATE PROCEDURE add_dns_a(newdomain varchar(256), newip inet)
LANGUAGE SQL
AS \$$
INSERT INTO ${dbname}.dns_a(name, ip)
  SELECT newdomain, newip
  WHERE NOT EXISTS (SELECT 1 FROM ${dbname}.dns_a WHERE name=newdomain AND ip=newip);
\$$;

DROP PROCEDURE IF EXISTS insert_ip;
CREATE PROCEDURE insert_ip(newip inet)
LANGUAGE SQL
AS \$$
INSERT INTO ${dbname}.${IP_HISTORY}(ip)
  SELECT newip
  WHERE NOT EXISTS (
    SELECT 1
    FROM ${dbname}.${IP_HISTORY}
    WHERE ip=newip);
\$$;
--------------------
DROP PROCEDURE IF EXISTS insert_upip;
CREATE PROCEDURE insert_upip(newip inet)
LANGUAGE SQL
AS \$$
INSERT INTO ${dbname}.${IP_HISTORY}(ip,is_up)
  SELECT newip, true
  WHERE NOT EXISTS (
    SELECT 1
    FROM (
      SELECT ip, max(timestamp) as maxtime
      FROM ${dbname}.${IP_HISTORY}
      WHERE ip=newip
      GROUP BY ip
    ) recent,
    ${dbname}.${IP_HISTORY} original
    WHERE original.ip=recent.ip
    AND recent.maxtime=original.timestamp
    AND original.is_up=true);
\$$;
DROP PROCEDURE IF EXISTS insert_downip;
CREATE PROCEDURE insert_downip(newip inet)
LANGUAGE SQL
AS \$$
INSERT INTO ${dbname}.${IP_HISTORY}(ip,is_up)
  SELECT newip, false
  WHERE NOT EXISTS (
    SELECT 1
    FROM (
      SELECT ip, max(timestamp) as maxtime
      FROM ${dbname}.${IP_HISTORY}
      WHERE ip=newip
      GROUP BY ip
    ) recent,
    ${dbname}.${IP_HISTORY} original
    WHERE original.ip=recent.ip
    AND recent.maxtime=original.timestamp
    AND original.is_up=false);
\$$;
"""
    echo "${template}" | psql -U postgres
}

add_ips() {
    local dbname
    dbname="$(parse ${1})"
    local ret=""
    while read -r ip; do ret+="CALL insert_ip('${ip}');"; done
    echo "${ret}" | psql -U postgres
}

add_ips_up() {
    local dbname
    dbname="$(parse ${1})"
    local ret=""
    while read -r ip; do ret+="CALL insert_downip('${ip}');"; done
    echo "${ret}" | psql -U postgres
}

add_ips_down() {
    local dbname
    dbname="$(parse ${1})"
    local ret=""
    while read -r ip; do ret+="CALL insert_downip('${ip}');"; done
    echo "${ret}" | psql -U postgres
}

get_ips_up(){
    local dbname
    dbname="$(parse ${1})"
    echo "CALL get_ips();" | psql -U postgres
}

add_dns_a(){
    local ret=""
    while read -r domain ip; do
        ret+="CALL add_dns_a('${domain}','${ip}')"
    done
}

parse(){
    domain="${1}"
    domain="${domain//./_}"
    echo "${domain}"
}

if [[ $_ == "$0" ]]; then
    cleardb "${1}"
    initdb  "${1}"
fi
