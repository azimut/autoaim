-- NOTE: Just saving some useful queries to be reused for cli queries or functions

--
-- DNS
--
CREATE OR REPLACE VIEW recent_tld_records AS
  SELECT current.*
  FROM (SELECT name,qtype,MAX(timestamp) AS maximun FROM tld_records GROUP BY name,qtype) recent
  JOIN tld_records current
  ON current.timestamp=recent.maximun AND current.name=recent.name AND current.qtype=recent.qtype;

CREATE OR REPLACE VIEW recent_dns_record AS
  SELECT current.*
  FROM (SELECT name,qtype,MAX(timestamp) AS maximun FROM dns_record GROUP BY name,qtype) recent
  JOIN dns_record current
  ON current.timestamp=recent.maximun AND current.name=recent.name AND current.qtype=recent.qtype;

CREATE OR REPLACE VIEW recent_dns_other AS
  SELECT current.*
  FROM (SELECT name,qtype,MAX(timestamp) AS maximun FROM dns_other GROUP BY name,qtype) recent
  JOIN dns_other current
  ON current.timestamp=recent.maximun AND current.name=recent.name AND current.qtype=recent.qtype;

--
-- IP
--
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
