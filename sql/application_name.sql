-- Create test table
CREATE TABLE appname1 (col int);
CREATE TABLE appname2 (col int);

-- Check if the READ class audit log is emitted only during
-- application_name is 'appname1'.
SELECT * FROM appname1;
SET application_name TO 'appname1';
SELECT * FROM appname1; -- must be logged
SET application_name TO DEFAULT;
SELECT * FROM appname1;

-- Check if the ERROR class audit log is emitted only during
-- application_name is 'appname2'.
SELECT err_col FROM appname2; -- error
SET application_name TO 'appname2';
SELECT err_col FROM appname2; -- error, must be logged
SET application_name TO DEFAULT ;
SELECT err_col FROM appname2; -- error
