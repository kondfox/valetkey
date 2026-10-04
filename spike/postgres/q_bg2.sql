\set VERBOSITY terse
BEGIN READ ONLY;
\echo --- single statement: set_config(default_transaction_read_only=off) then pg_background_run
SELECT set_config('default_transaction_read_only','off',true) AS s, (SELECT error_message FROM pg_background_run($$INSERT INTO t VALUES (104,'pg_background after set_config')$$, 0, 5000)) AS err;
ROLLBACK;
BEGIN READ ONLY;
\echo --- postgres_fdw SELECT from foreign table over a writing remote view
SELECT * FROM fvw;
ROLLBACK;
