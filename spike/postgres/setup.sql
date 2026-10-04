CREATE TABLE t(id int, v text);
INSERT INTO t VALUES (1,'one');
CREATE SEQUENCE s;
CREATE ROLE r_exec LOGIN IN ROLE pg_execute_server_program;
CREATE ROLE r_wfile LOGIN IN ROLE pg_write_server_files;
CREATE ROLE r_rfile LOGIN IN ROLE pg_read_server_files;
CREATE ROLE r_plain LOGIN;
CREATE ROLE r_other LOGIN;
GRANT ALL ON t, s TO r_exec, r_wfile, r_rfile, r_plain;
