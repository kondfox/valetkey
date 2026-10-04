\set VERBOSITY terse
\echo --- r_exec: COPY TO PROGRAM in BEGIN READ ONLY
SET ROLE r_exec;
SHOW default_transaction_read_only;
BEGIN READ ONLY;
COPY (SELECT 1) TO PROGRAM 'touch /tmp/pwned';
ROLLBACK;
\echo --- r_exec: COPY FROM PROGRAM into table
BEGIN READ ONLY;
COPY t(v) FROM PROGRAM 'echo x';
ROLLBACK;
\echo --- r_exec: COPY (SELECT) TO PROGRAM output as SELECT program (no txn block, default ro)
COPY (SELECT 1) TO PROGRAM 'id > /tmp/pwned2';
RESET ROLE;
\echo --- r_wfile: COPY TO file
SET ROLE r_wfile;
BEGIN READ ONLY;
COPY (SELECT 'hi') TO '/tmp/x';
ROLLBACK;
RESET ROLE;
\echo --- r_rfile: COPY t FROM file
SET ROLE r_rfile;
BEGIN READ ONLY;
COPY t(v) FROM '/etc/hostname';
ROLLBACK;
BEGIN READ ONLY;
SELECT length(pg_read_file('/etc/passwd')) AS passwd_len;
SELECT count(*) FROM pg_ls_dir('/') ;
SELECT lo_import('/etc/passwd');
ROLLBACK;
RESET ROLE;
