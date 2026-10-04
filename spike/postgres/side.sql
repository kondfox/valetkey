\set VERBOSITY terse
SHOW default_transaction_read_only;
BEGIN READ ONLY;
\echo --- advisory lock (session-level) + xact
SELECT pg_advisory_lock(42), pg_try_advisory_xact_lock(43);
\echo --- nextval / setval
SELECT nextval('s');
ROLLBACK;
BEGIN READ ONLY;
SELECT setval('s', 1000);
ROLLBACK;
BEGIN READ ONLY;
\echo --- pg_notify
SELECT pg_notify('chan','hello from RO');
COMMIT;
BEGIN READ ONLY;
\echo --- pg_terminate_backend on other role (r_other)
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='r_other';
ROLLBACK;
BEGIN READ ONLY;
\echo --- pg_cancel_backend on same role (other r_plain session)
SELECT pid, pg_cancel_backend(pid) FROM pg_stat_activity WHERE usename='r_plain' AND pid<>pg_backend_pid();
ROLLBACK;
BEGIN READ ONLY;
\echo --- pg_terminate_backend on same role (other r_plain session)
SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='r_plain' AND pid<>pg_backend_pid() AND query LIKE '%pg_sleep%';
ROLLBACK;
BEGIN READ ONLY;
\echo --- SET TRANSACTION READ WRITE as first stmt after BEGIN READ ONLY
SET TRANSACTION READ WRITE;
INSERT INTO t VALUES (400,'after SET TRANSACTION READ WRITE');
COMMIT;
BEGIN READ ONLY;
SELECT 1;
\echo --- SET TRANSACTION READ WRITE after a snapshot was taken
SET TRANSACTION READ WRITE;
ROLLBACK;
BEGIN READ ONLY;
\echo --- set_config transaction_read_only off, then INSERT via same statement?
SELECT set_config('transaction_read_only','off',true);
ROLLBACK;
BEGIN READ ONLY;
\echo --- DO block with COMMIT inside an explicit RO txn
DO $$BEGIN COMMIT; SET TRANSACTION READ WRITE; INSERT INTO t VALUES (401,'DO commit in txn'); END$$;
ROLLBACK;
\echo --- DO block with COMMIT, NO explicit txn (only default_transaction_read_only)
DO $$BEGIN SET default_transaction_read_only = off; COMMIT; INSERT INTO t VALUES (402,'DO commit no txn'); END$$;
\echo --- session advisory lock still held after ROLLBACK?
SELECT count(*) AS my_advisory_locks FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid();
