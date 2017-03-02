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

-- Test log parameter
BEGIN;
PREPARE prep_dx AS SELECT * FROM pg_extension WHERE extname = $1 AND extversion = $2;
EXECUTE prep_dx ('plpgsql','1.0');
EXECUTE prep_dx ('hogehoge','2.0');
DEALLOCATE PREPARE prep_dx;
COMMIT;

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

--
-- Test for trigger. Corresponding RULE 2.
--

-- Set up DDLs are logged.
CREATE TABLE trig_test(v text);
CREATE TABLE trig_audit(
operation char(1) NOT NULL,
stamp timestamp NOT NULL,
userid text NOT NULL,
old_value text,
new_value text
);
CREATE OR REPLACE FUNCTION process_trig_audit() RETURNS TRIGGER AS $emp_audit$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO trig_audit SELECT 'D', now(), user, OLD.*, NULL;
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO trig_audit SELECT 'U', now(), user, OLD.*, NEW.*;
        RETURN NEW;
   ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO trig_audit SELECT 'I', now(), user, NULL, NEW.*;
        RETURN NEW;
   END IF;
        RETURN NULL;
END;
$emp_audit$ LANGUAGE plpgsql;
CREATE TRIGGER trig_audit AFTER INSERT OR UPDATE OR DELETE ON trig_test
FOR EACH ROW EXECUTE PROCEDURE process_trig_audit();


-- Check if the following trigger operations are logged as well.
-- INSERT, logged
INSERT INTO trig_test VALUES ('new value');

-- UPDATE, logged
UPDATE trig_test SET v = 'updated value';

-- DELETE, logged
DELETE FROM trig_test; -- delete 1 row

-- SELECT, not logged
SELECT count(*) FROM trig_test;
SELECT count(*) FROM trig_audit;
