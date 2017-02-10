--
-- Note:
-- In order to install pgaudit first, the initial pgaudit config
-- file is 'empty.conf' located in conf/ directory. After installed
-- pgaudit, change config file to properly file 'audit.conf' and
-- restart it.
--
CREATE EXTENSION pgaudit;
-- check installation.
SELECT extname, extversion FROM pg_extension;
-- check pgaudit event triggers.
SELECT evtname, evtevent FROM pg_event_trigger WHERE evtname LIKE 'pgaudit%';

-- Install pgaudit in other databases
SELECT current_database() \gset
CREATE DATABASE foo;
CREATE DATABASE bar;
\c foo
CREATE EXTENSION pgaudit;
SELECT extname, extversion FROM pg_extension;
SELECT evtname, evtevent FROM pg_event_trigger WHERE evtname LIKE 'pgaudit%';
\c bar
CREATE EXTENSION pgaudit;
SELECT extname, extversion FROM pg_extension;
SELECT evtname, evtevent FROM pg_event_trigger WHERE evtname LIKE 'pgaudit%';

-- Change config file to properly file.
ALTER SYSTEM SET pgaudit.config_file TO '../../conf/audit.conf';
\! pg_ctl restart -w -D ./tmp_check/data > /dev/null
-- Connection will be disconnected, close connection explicitly .
\q
