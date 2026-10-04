-- superuser-owned wrappers in languages the draft query ignores
CREATE FUNCTION f_internal_read(text) RETURNS text LANGUAGE internal STRICT SECURITY DEFINER AS 'pg_read_file_all';
CREATE FUNCTION f_plpgsql_prog(cmd text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN EXECUTE format('COPY (SELECT 1) TO PROGRAM %L', cmd); END $$;
