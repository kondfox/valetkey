ALTER ROLE r_plain PASSWORD 'plainpw';
CREATE EXTENSION dblink; CREATE EXTENSION postgres_fdw; CREATE EXTENSION pg_background; CREATE EXTENSION http; CREATE EXTENSION pg_net;
GRANT USAGE ON FOREIGN DATA WRAPPER postgres_fdw TO r_plain;
CREATE SERVER loop FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'localhost', dbname 'postgres');
CREATE USER MAPPING FOR r_plain SERVER loop OPTIONS (user 'r_plain', password 'plainpw');
CREATE FOREIGN TABLE ft (id int, v text) SERVER loop OPTIONS (table_name 't');
GRANT ALL ON ft TO r_plain;
GRANT USAGE ON SCHEMA net TO r_plain; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA net TO r_plain;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO r_plain;
