CREATE USER test_auditor;
CREATE TABLE IF NOT EXISTS foo (id int, data text);
CREATE TABLE IF NOT EXISTS bar (id int, data text);
CREATE TABLE IF NOT EXISTS baz (id int, data text);

GRANT ALL ON foo TO test_auditor;

SELECT * FROM foo;
SELECT foo.id, bar.data FROM foo, bar WHERE foo.id = bar.id;
SELECT foo.id, bar.data, baz.data FROM foo, bar, baz WHERE foo.id = bar.id AND foo.id = baz.id;

DROP TABLE IF EXISTS foo;
DROP TABLE IF EXISTS bar;
DROP TABLE IF EXISTS baz;
DROP USER test_auditor;

