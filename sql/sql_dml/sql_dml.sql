\! echo "" >  /tmp/__sql_dml_in.data

CREATE TABLE foo (id int, data text);
CREATE TABLE foo_copy (id int, data text);

INSERT INTO foo (id, data) VALUES (1, 'aaa'),(2, 'bbb'),(3, 'ccc');

COPY foo FROM '/tmp/__sql_dml_in.data';

INSERT INTO foo_copy SELECT * FROM foo;

COPY foo TO '/tmp/__sql_dml_out.data';
COPY (SELECT * FROM foo_copy WHERE id = 2) TO '/tmp/__sql_dml_out.data';

SELECT 1;
SELECT * FROM (SELECT generate_series(1, 10) as seq) as series;
SELECT * FROM foo WHERE id = 3;
SELECT foo.id, foo_copy.data FROM foo INNER JOIN foo_copy ON foo.id = foo_copy.id WHERE foo.id = 2;

UPDATE foo SET data = 'BBB' WHERE id = 2;
DELETE FROM foo WHERE id = 2;

TRUNCATE foo,foo_copy;

DROP TABLE foo_copy;
DROP TABLE foo;

