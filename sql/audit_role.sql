CREATE USER audit_role SUPERUSER;
CREATE USER unaudit_role;

-- Operations by unaudit_role should not be logged.
\c bar unaudit_role
CREATE TABLE role_test(c int primary key);
INSERT INTO role_test VALUES(1);
SELECT * FROM role_test;
DROP TABLE role_test;

-- Operation by audit_role should be logged
-- according to configuration. DDL and READ
-- are logged.
\c bar audit_role
-- logged
CREATE TABLE role_test(c int primary key);
-- not logged
INSERT INTO role_test VALUES(1);
-- logged
SELECT * FROM role_test;
-- logged
DROP TABLE role_test;

-- SET ROLE doesn't work to avoid emit
SET ROLE unaudit_role;
CREATE TABLE role_test(c int primary key);
INSERT INTO role_test VALUES(1);
SELECT * FROM role_test;
DROP TABLE role_test;
