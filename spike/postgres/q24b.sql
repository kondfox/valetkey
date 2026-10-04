\set VERBOSITY terse
SHOW default_transaction_read_only;
BEGIN READ ONLY;
\echo --- dblink_exec INSERT
SELECT dblink_exec('host=localhost dbname=postgres user=r_plain password=plainpw', $$INSERT INTO t VALUES (100,'via dblink')$$);
ROLLBACK;
BEGIN READ ONLY;
\echo --- dblink() with a writing query (SELECT ... from INSERT RETURNING)
SELECT * FROM dblink('host=localhost dbname=postgres user=r_plain password=plainpw', $$INSERT INTO t VALUES (101,'via dblink select') RETURNING id$$) AS x(id int);
ROLLBACK;
BEGIN READ ONLY;
\echo --- postgres_fdw INSERT into foreign table
INSERT INTO ft VALUES (102,'via fdw');
ROLLBACK;
BEGIN READ ONLY;
\echo --- postgres_fdw: remote function with side effects via SELECT? (postgres_fdw remote txn mode)
SELECT count(*) FROM ft;
ROLLBACK;
BEGIN READ ONLY;
\echo --- pg_background_launch INSERT
SELECT * FROM pg_background_result(pg_background_launch($$INSERT INTO t VALUES (103,'via pg_background')$$)) AS (r text);
ROLLBACK;
BEGIN READ ONLY;
\echo --- pg_net http_get
SELECT net.http_get('http://example.com/?leak=pgnet');
ROLLBACK;
BEGIN READ ONLY;
\echo --- http extension http_get
SELECT status FROM http_get('http://example.com/?leak=http');
ROLLBACK;
