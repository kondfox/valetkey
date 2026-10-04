DELETE FROM t WHERE id>1;
SELECT pg_background_grant_privileges('r_plain', true);
CREATE FUNCTION w() RETURNS int LANGUAGE sql VOLATILE AS $$ INSERT INTO t VALUES (200,'via fdw remote view') RETURNING id $$;
CREATE VIEW vw AS SELECT w() AS id;
GRANT SELECT ON vw TO r_plain;
CREATE FOREIGN TABLE fvw (id int) SERVER loop OPTIONS (table_name 'vw');
GRANT SELECT ON fvw TO r_plain;
