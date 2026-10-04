\set VERBOSITY terse
SHOW default_transaction_read_only;
BEGIN READ ONLY;
SELECT f_os();
ROLLBACK;
BEGIN READ ONLY;
SELECT f_write();
ROLLBACK;
BEGIN READ ONLY;
SELECT f_perl();
ROLLBACK;
