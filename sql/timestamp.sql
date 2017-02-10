-- Create test table
CREATE TABLE timestamp_test1(col timestamp);
CREATE TABLE timestamp_test2(col timestamp);

-- Check if the audit logging for timestamp_test1 is logged and
-- the audit logging for timestamp_test2 is NOT logged now.
SELECT * FROM timestamp_test1;
SELECT * FROM timestamp_test2;

-- Wait until past the timestamp range.
SELECT pg_sleep(extract(second from (date_trunc('min', now() + '1 min')  - now()))::int + 3);

-- Check if the audit logging for timestamp_test1 is NOT logged and
-- the audit logging for timestamp_test2 is logged now.
SELECT * FROM timestamp_test1;
SELECT * FROM timestamp_test2;




