CREATE TABLE foo (id int, data text);
CREATE FUNCTION foo_add(p1 int, p2 int) RETURNS integer AS $$
DECLARE
  ret int;
BEGIN
        ret := p1 + p2;
        return ret;
END;
$$ LANGUAGE plpgsql ;

BEGIN;
SELECT foo_add(10, 20);
INSERT INTO foo VALUES (1, 'aaa'),(2,'bbb');
TABLE foo;
UPDATE foo SET data = 'BBB' WHERE id = 2;
DELETE FROM foo WHERE id = 1;
SELECT * FROM foo;
TRUNCATE foo;
COMMIT;

DROP FUNCTION foo_add(p1 int, p2 int);
DROP TABLE foo;

