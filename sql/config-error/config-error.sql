CREATE TABLE test (id int primary key, data text);
INSERT INTO test VALUES (1, 'AAA'),(2, 'BBB');
UPDATE test SET data = 'XXX' WHERE id = 3;
DELETE FROM test WHERE id = 4;
SELECT * FROM test;
TRUNCATE test;
DROP TABLE test;
