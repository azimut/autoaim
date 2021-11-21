DROP PROCEDURE IF EXISTS add_tld(varchar,varchar,varchar,varchar,varchar,varchar);
DROP PROCEDURE IF EXISTS add_tld(varchar,varchar,varchar,varchar,varchar,inet);

CREATE PROCEDURE add_tld(newdomain VARCHAR,
                         newroot   VARCHAR,
                         newqtype  VARCHAR,
                         newrtype  VARCHAR,
                         newrcode  VARCHAR,
                         newdata   VARCHAR)
LANGUAGE SQL
AS \$$
INSERT INTO tld_records(name, root, qtype, rtype, rcode, data)
SELECT LOWER(newdomain),
       LOWER(newroot),
       UPPER(newqtype),
       UPPER(newrtype),
       UPPER(newrcode),
       newdata
WHERE NOT EXISTS (
    SELECT 1
    FROM recent_tld_records
    WHERE name=newdomain
      AND root=newroot
      AND rcode=newrcode
      AND ((data IS NULL AND newdata IS NULL) OR data=newdata));
\$$;

CREATE PROCEDURE add_tld(newdomain VARCHAR,
                         newroot   VARCHAR,
                         newqtype  VARCHAR,
                         newrtype  VARCHAR,
                         newrcode  VARCHAR,
                         newip     INET)
LANGUAGE SQL
AS \$$
INSERT INTO tld_records(name, root, qtype, rtype, rcode, ip)
SELECT LOWER(newdomain),
       LOWER(newroot),
       UPPER(newqtype),
       newrtype,
       newrcode,
       newip
WHERE NOT EXISTS (
    SELECT 1
    FROM recent_tld_records
    WHERE name=newdomain
      AND root=newroot
      AND rcode=newrcode
      AND ((ip IS NULL AND newip IS NULL) OR ip=newip));
\$$;
