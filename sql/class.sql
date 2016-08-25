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
DO $$ BEGIN EXECUTE 'select ' || '1'; END$$;
