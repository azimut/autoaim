DROP PROCEDURE IF EXISTS insert_ip(inet, boolean, timestamp);
DROP PROCEDURE IF EXISTS insert_ip(inet, boolean);
DROP PROCEDURE IF EXISTS insert_ip(inet);
DROP PROCEDURE IF EXISTS insert_ip;

CREATE PROCEDURE insert_ip(newip INET)
LANGUAGE SQL
AS \$$
INSERT INTO ip_history(ip)
SELECT newip
WHERE NOT EXISTS (
    SELECT 1
    FROM ip_history
    WHERE ip=newip);
\$$;

CREATE PROCEDURE insert_ip(newip INET, state BOOLEAN)
LANGUAGE SQL
AS \$$
INSERT INTO ip_history(ip,is_up)
SELECT newip, state
WHERE NOT EXISTS (
    SELECT 1
    FROM (
        SELECT ip, max(timestamp) as maxtime
        FROM ip_history
        WHERE ip=newip
        GROUP BY ip
    ) recent,
    ip_history original
    WHERE original.ip=recent.ip
    AND recent.maxtime=original.timestamp
    AND original.is_up=state);
\$$;

CREATE PROCEDURE insert_ip(newip INET, state BOOLEAN, newtime TIMESTAMP WITH TIME ZONE)
LANGUAGE SQL
AS \$$
INSERT INTO ip_history(ip,is_up,timestamp)
SELECT newip, state, newtime
WHERE NOT EXISTS (
    SELECT 1
    FROM ip_history
    WHERE ip=newip
      AND timestamp=newtime
      AND is_up=state);
\$$;

DROP PROCEDURE IF EXISTS insert_upip;
CREATE PROCEDURE insert_upip(newip INET)
LANGUAGE SQL
AS \$$
INSERT INTO ip_history(ip,is_up)
SELECT newip, true
WHERE NOT EXISTS (
    SELECT 1
    FROM (
        SELECT ip, max(timestamp) as maxtime
        FROM ip_history
        WHERE ip=newip
        GROUP BY ip
    ) recent,
    ip_history original
    WHERE original.ip=recent.ip
    AND recent.maxtime=original.timestamp
    AND original.is_up=true);
\$$;

DROP PROCEDURE IF EXISTS insert_downip;
CREATE PROCEDURE insert_downip(newip INET)
LANGUAGE SQL
AS \$$
INSERT INTO ip_history(ip,is_up)
SELECT newip, false
WHERE NOT EXISTS (
    SELECT 1
    FROM (
        SELECT ip, max(timestamp) as maxtime
        FROM ip_history
        WHERE ip=newip
        GROUP BY ip
    ) recent,
    ip_history original
    WHERE original.ip=recent.ip
    AND recent.maxtime=original.timestamp
    AND original.is_up=false);
\$$;


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

DROP PROCEDURE IF EXISTS insert_ip_data;
CREATE PROCEDURE insert_ip_data(newip   INET,
                                newcidr CIDR,
                                newasn  VARCHAR)
LANGUAGE SQL
AS \$$
INSERT INTO ip_data(ip, cidr, asn)
SELECT newip, newcidr, newasn
WHERE NOT EXISTS (
    SELECT 1
    FROM (
        SELECT ip, max(timestamp) as maxtime
        FROM ip_data
        WHERE ip=newip
        GROUP BY ip
    ) recent,
    ip_data original
    WHERE original.ip=recent.ip
      AND recent.maxtime=original.timestamp
      AND ( ( original.cidr=newcidr AND original.asn=newasn) OR
            ( original.cidr IS NULL AND newcidr IS NULL)));
\$$;
