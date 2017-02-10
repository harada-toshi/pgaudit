\c foo
-- DDL, logged.
CREATE TABLE a1 (col int primary key);
ALTER TABLE a1 SET (fillfactor = 100);
-- READ, logged.
SELECT * FROM a1;
-- WRITE, logged.
INSERT INTO a1 VALUES(1);
UPDATE a1 SET col = col;
-- MISC, not logged.
VACUUM a1;
REINDEX TABLE a1;
-- ROLE, logged.
CREATE USER test_user;
GRANT ALL ON a1 To test_user;
-- FUNCTION, logged.
DO $$ BEGIN EXECUTE 'select ' || '* FROM a1'; END$$;
-- DROP table
DROP TABLE a1;

\c baz
-- DDL, logged
CREATE TABLE a2 (c int primary key);
-- READ, not logged
SELECT  * FROM a2;
-- DDL and READ
CREATE VIEW a2_view AS SELECT * FROM a2;
-- WRITE, logged
INSERT INTO a2 VALUES(1);
UPDATE a2 SET c = c;
-- DDL, logged
ALTER TABLE a2 SET (fillfactor = 100);
-- DDL, logged
CREATE FUNCTION test_func() RETURNS INT AS
$$
BEGIN
    RETURN 0;
END;
$$ LANGUAGE plpgsql;
-- FUNCTION, not logged
SELECT test_func();
-- ROLE, not logged
ALTER USER foo_user SUPERUSER;
ALTER USER foo_user NOSUPERUSER;
-- MISC, not logged
VACUUM a2;
