DROP PROCEDURE IF EXISTS add_dns(varchar,varchar,varchar,varchar,varchar,varchar);
DROP PROCEDURE IF EXISTS add_dns(varchar,varchar,varchar,varchar,varchar,inet);

CREATE PROCEDURE add_dns(newdomain VARCHAR, newroot VARCHAR, newqtype VARCHAR, newrtype VARCHAR, newrcode VARCHAR, newdata VARCHAR)
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
    FROM recent_dns_record
    WHERE name=newdomain
      AND root=newroot
      AND qtype=newqtype
      AND (rcode=newrcode OR (rcode IS NULL AND newrcode IS NULL))
      AND ((data IS NULL AND newdata IS NULL) OR data=newdata));
\$$;

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
    FROM recent_dns_record
    WHERE name=newdomain
      AND root=newroot
      AND qtype=newqtype
      AND (rcode=newrcode OR (rcode IS NULL AND newrcode IS NULL))
      AND ((ip IS NULL AND newip IS NULL) OR ip=newip));
\$$;

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

DROP PROCEDURE IF EXISTS add_other(varchar,varchar,varchar,varchar,varchar);
CREATE PROCEDURE add_other(newdomain VARCHAR,
                         newqtype  VARCHAR,
                         newrtype  VARCHAR,
                         newrcode  VARCHAR,
                         newdata   VARCHAR)
LANGUAGE SQL
AS \$$
INSERT INTO dns_other(name, qtype, rtype, rcode, data)
SELECT LOWER(newdomain),
       UPPER(newqtype),
       newrtype,
       newrcode,
       newdata
WHERE NOT EXISTS (
    SELECT 1
    FROM recent_dns_other
    WHERE name=newdomain
    AND rcode=newrcode
    AND ((data IS NULL AND newdata IS NULL) OR data=newdata));
\$$;
DROP PROCEDURE IF EXISTS add_other(varchar,varchar,varchar,varchar,inet);
CREATE PROCEDURE add_other(newdomain VARCHAR,
                         newqtype  VARCHAR,
                         newrtype  VARCHAR,
                         newrcode  VARCHAR,
                         newip     INET)
LANGUAGE SQL
AS \$$
INSERT INTO dns_other(name, qtype, rtype, rcode, ip)
SELECT LOWER(newdomain),
       UPPER(newqtype),
       newrtype,
       newrcode,
       newip
WHERE NOT EXISTS (
    SELECT 1
    FROM recent_dns_other
    WHERE name=newdomain
    AND rcode=newrcode
    AND ((ip IS NULL AND newip IS NULL) OR ip=newip));
\$$;
