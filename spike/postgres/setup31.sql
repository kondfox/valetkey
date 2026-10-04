CREATE EXTENSION plpython3u; CREATE EXTENSION plperlu; CREATE EXTENSION pgcrypto; CREATE EXTENSION pg_stat_statements;
CREATE FUNCTION f_os() RETURNS text LANGUAGE plpython3u SECURITY DEFINER AS $$
import subprocess
return subprocess.run(['sh','-c','id > /tmp/plpy_pwned; id'], capture_output=True, text=True).stdout
$$;
CREATE FUNCTION f_write() RETURNS text LANGUAGE plpython3u SECURITY DEFINER AS $$
plpy.execute("INSERT INTO t VALUES (300,'via plpython SPI')")
return 'ok'
$$;
CREATE FUNCTION f_perl() RETURNS text LANGUAGE plperlu SECURITY DEFINER AS $$ return `id`; $$;
CREATE FUNCTION f_c_shim(text) RETURNS text LANGUAGE c STRICT AS '$libdir/pgcrypto', 'pg_digest';  -- hand-made C function, not part of an extension
