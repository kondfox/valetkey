\set VERBOSITY terse
SHOW default_transaction_read_only;
BEGIN READ ONLY;
\echo --- pg_background_run INSERT
SELECT state, command_tag, has_error, error_message FROM pg_background_run($$INSERT INTO t VALUES (103,'via pg_background ' || current_setting('default_transaction_read_only'))$$, 0, 5000);
ROLLBACK;
BEGIN READ ONLY;
\echo --- postgres_fdw SELECT from foreign table over a writing remote view
SELECT * FROM fvw;
ROLLBACK;
