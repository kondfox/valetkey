\set VERBOSITY terse
SHOW default_transaction_read_only;
BEGIN READ ONLY;
\echo --- dblink_exec INSERT
SELECT dblink_exec('host=172.17.0.3 dbname=postgres user=r_plain password=plainpw', $$INSERT INTO t VALUES (100,'via dblink_exec')$$);
ROLLBACK;
BEGIN READ ONLY;
\echo --- dblink() INSERT RETURNING
SELECT * FROM dblink('host=172.17.0.3 dbname=postgres user=r_plain password=plainpw', $$INSERT INTO t VALUES (101,'via dblink()') RETURNING id$$) AS x(id int);
ROLLBACK;
BEGIN READ ONLY;
\echo --- postgres_fdw INSERT into foreign table
INSERT INTO ft VALUES (102,'via fdw');
ROLLBACK;
BEGIN READ ONLY;
\echo --- postgres_fdw SELECT (remote read ok)
SELECT count(*) FROM ft;
ROLLBACK;
BEGIN READ ONLY;
\echo --- pg_background_run INSERT
SELECT state, command_tag, has_error, error_message FROM pg_background_run($$INSERT INTO t VALUES (103,'via pg_background')$$, 0, 5000);
ROLLBACK;
