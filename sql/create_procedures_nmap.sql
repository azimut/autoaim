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
INSERT INTO nmap_scan(timestamp, ip, host, pstatus, proto, port, service, finger)
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
