\set VERBOSITY terse
BEGIN READ ONLY;
SELECT length(f_internal_read('/etc/shadow')) AS shadow_len;
ROLLBACK;
BEGIN READ ONLY;
SELECT f_plpgsql_prog('touch /tmp/plpgsql_definer_pwned');
ROLLBACK;
