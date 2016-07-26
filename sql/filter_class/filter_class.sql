CREATE TABLE IF NOT EXISTS foo(id int, data text);
BEGIN;
INSERT INTO foo VALUES (1, 'aaa');
UPDATE foo SET data = 'AAA' WHERE id = 1;
SELECT * FROM foo;
DELETE FROM foo;
TRUNCATE foo;
COMMIT;
DROP TABLE foo;

