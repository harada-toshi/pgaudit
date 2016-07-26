CREATE TABLE IF NOT EXISTS foo(id int, data text);
CREATE TABLE IF NOT EXISTS bar(id int, data text);
BEGIN;
INSERT INTO foo VALUES (1, 'aaa');
INSERT INTO bar VALUES (1, 'xxx');
UPDATE foo SET data = 'AAA' WHERE id = 1;
UPDATE bar SET data = 'XXX' WHERE id = 1;
SELECT * FROM foo;
SELECT * FROM bar;
DELETE FROM foo;
DELETE FROM bar;
TRUNCATE foo;
TRUNCATE bar;
COMMIT;
DROP TABLE foo;
DROP TABLE bar;

