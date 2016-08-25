CREATE USER foo_user;
CREATE USER bar_user;
CREATE DATABASE foo;
CREATE DATABASE bar;

-- Audit log must be logged
\c foo foo_user
SELECT 1;

-- Audit log must not be logged
\c bar foo_user
SELECT 2;
