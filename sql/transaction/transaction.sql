-- explicitly transaction
BEGIN;
CREATE TABLE foo (id int, data text);
INSERT INTO foo VALUES (1,'aaa'),(2,'bbb'),(3,'ccc');
UPDATE foo SET data = 'CCC' WHERE id = 3;
DELETE FROM foo WHERE id = 2;
SELECT * FROM foo;
TRUNCATE foo;
DROP TABLE foo;
COMMIT;

BEGIN;
CREATE TABLE foo (id int, data text);
INSERT INTO foo VALUES (1,'aaa'),(2,'bbb'),(3,'ccc');
UPDATE foo SET data = 'CCC' WHERE id = 3;
DELETE FROM foo WHERE id = 2;
SELECT * FROM foo;
TRUNCATE foo;
DROP TABLE foo;
END;

BEGIN;
CREATE TABLE foo (id int, data text);
INSERT INTO foo VALUES (1,'aaa'),(2,'bbb'),(3,'ccc');
UPDATE foo SET data = 'CCC' WHERE id = 3;
DELETE FROM foo WHERE id = 2;
SELECT * FROM foo;
TRUNCATE foo;
DROP TABLE foo;
ROLLBACK;

BEGIN;
CREATE TABLE foo (id int, data text);
INSERT INTO foo VALUES (1,'aaa'),(2,'bbb'),(3,'ccc');
UPDATE foo SET data = 'CCC' WHERE id = 3;
DELETE FROM foo WHERE id = 2;
SELECT * FROM foo;
TRUNCATE foo;
SELECT ERROR1; -- syntax error
ROLLBACK;


-- autocommit off
\set AUTOCOMMIT off

CREATE TABLE foo (id int, data text);
INSERT INTO foo VALUES (1,'aaa'),(2,'bbb'),(3,'ccc');
UPDATE foo SET data = 'CCC' WHERE id = 3;
DELETE FROM foo WHERE id = 2;
SELECT * FROM foo;
TRUNCATE foo;
DROP TABLE foo;
COMMIT;

-- implicit transaction
CREATE TABLE foo (id int, data text);
INSERT INTO foo VALUES (1,'aaa'),(2,'bbb'),(3,'ccc');
UPDATE foo SET data = 'CCC' WHERE id = 3;
DELETE FROM foo WHERE id = 2;
SELECT * FROM foo;
TRUNCATE foo;
DROP TABLE foo;
END;

CREATE TABLE foo (id int, data text);
INSERT INTO foo VALUES (1,'aaa'),(2,'bbb'),(3,'ccc');
UPDATE foo SET data = 'CCC' WHERE id = 3;
DELETE FROM foo WHERE id = 2;
SELECT * FROM foo;
TRUNCATE foo;
DROP TABLE foo;
ROLLBACK;

CREATE TABLE foo (id int, data text);
INSERT INTO foo VALUES (1,'aaa'),(2,'bbb'),(3,'ccc');
UPDATE foo SET data = 'CCC' WHERE id = 3;
DELETE FROM foo WHERE id = 2;
SELECT * FROM foo;
TRUNCATE foo;
SELECT ERROR1; -- syntax error
ROLLBACK;

-- autocommit
\set AUTOCOMMIT on

CREATE TABLE foo (id int, data text);
INSERT INTO foo VALUES (1,'aaa'),(2,'bbb'),(3,'ccc');
UPDATE foo SET data = 'CCC' WHERE id = 3;
SELECT ERROR1; -- syntax error
DELETE FROM foo WHERE id = 2;
SELECT * FROM foo;
SELECT ERROR2; -- syntax error
TRUNCATE foo;
DROP TABLE foo;

