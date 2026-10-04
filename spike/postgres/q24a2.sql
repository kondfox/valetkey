\set VERBOSITY terse
SET ROLE r_exec;
BEGIN READ ONLY;
COPY t(v) FROM PROGRAM 'touch /tmp/fromprog';
ROLLBACK;
RESET ROLE;
\echo --- pg_read_server_files: grants
SELECT has_function_privilege('r_rfile','pg_read_file(text)','EXECUTE') rf, has_function_privilege('r_rfile','pg_ls_dir(text)','EXECUTE') ls, has_function_privilege('r_rfile','lo_import(text)','EXECUTE') lo;
\echo --- after GRANT EXECUTE on pg_read_file to r_rfile
GRANT EXECUTE ON FUNCTION pg_read_file(text) TO r_rfile;
SET ROLE r_rfile;
BEGIN READ ONLY;
SELECT length(pg_read_file('/etc/passwd')) AS passwd_len;
ROLLBACK;
RESET ROLE;
\echo --- superuser lo_import in RO
BEGIN READ ONLY;
SELECT lo_import('/etc/passwd');
ROLLBACK;
REVOKE EXECUTE ON FUNCTION pg_read_file(text) FROM r_rfile;
