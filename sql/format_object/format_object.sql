-- create objects
CREATE TABLE foo (id int, data text);
CREATE INDEX foo_id_idx ON foo USING btree (id);
CREATE VIEW foo_v AS SELECT * FROM foo;
CREATE MATERIALIZED VIEW foo_mv AS SELECT * FROM foo;
CREATE SEQUENCE dummy_seq;

INSERT INTO foo VALUES (1, 'aaa'),(2,'bbb');
REFRESH MATERIALIZED VIEW foo_mv;
REINDEX INDEX foo_id_idx;
REINDEX TABLE foo;
-- SELECT
TABLE foo;
TABLE foo_v;
TABLE foo_mv;

-- drp objects
DROP SEQUENCE dummy_seq;
DROP MATERIALIZED VIEW foo_mv;
DROP VIEW foo_v;
DROP INDEX foo_id_idx;
DROP TABLE foo;

