--
-- NMAP
--
CREATE TABLE IF NOT EXISTS nmap_scan(
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET NOT NULL,
    host      VARCHAR(256),
    pstatus   VARCHAR(24),
    proto     VARCHAR(8),
    port      INTEGER,
    service   VARCHAR(32),
    finger    VARCHAR(32));

--
-- DNS
--
CREATE TABLE IF NOT EXISTS dns_a_wildcard(
    base      VARCHAR(256) NOT NULL,
    root      VARCHAR(256) NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET);

CREATE TABLE IF NOT EXISTS tld_records(
    name      VARCHAR(256) NOT NULL,
    root      VARCHAR(256) NOT NULL,
    timestamp TIMESTAMP    DEFAULT NOW(),
    qtype     VARCHAR(16)  NOT NULL,
    rtype     VARCHAR(16),
    rcode     VARCHAR(16)  NOT NULL,
    data      VARCHAR(512),
    ip        INET);

CREATE TABLE IF NOT EXISTS dns_other(
    timestamp TIMESTAMP    DEFAULT NOW(),
    name      VARCHAR(256) NOT NULL,
    qtype     VARCHAR(16)  NOT NULL,
    rtype     VARCHAR(16),
    rcode     VARCHAR(16)  NOT NULL,
    data      VARCHAR(512),
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

CREATE INDEX IF NOT EXISTS root_index ON dns_record(root);

--
-- IP
--
CREATE TABLE IF NOT EXISTS ip_ptr (
    timestamp TIMESTAMP   DEFAULT NOW(),
    ip        INET        NOT NULL,
    rcode     VARCHAR(16) NOT NULL,
    ptr       VARCHAR(256));

CREATE TABLE IF NOT EXISTS ip_reverse (
    ip        INET         NOT NULL PRIMARY KEY,
    reverse   VARCHAR(256) NOT NULL);

CREATE TABLE IF NOT EXISTS ip_data(
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET NOT NULL,
    cidr      CIDR,
    asn       VARCHAR(256));

CREATE TABLE IF NOT EXISTS ip_history(
    timestamp TIMESTAMP DEFAULT NOW(),
    ip        INET NOT NULL,
    is_up     BOOLEAN);
