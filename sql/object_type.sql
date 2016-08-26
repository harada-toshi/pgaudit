\c foo
-- Setup relations
CREATE TABLE obj_type (col int primary key);
CREATE MATERIALIZED VIEW obj_type_mv AS SELECT * FROM obj_type;
CREATE VIEW obj_type_v AS SELECT * FROM obj_type;
CREATE SEQUENCE sq1;

-- TABLE, logged.
SELECT * FROM obj_type;

-- INDEX, not logged.
REINDEX INDEX obj_type_pkey;

-- SEQUENCE, logged.
SELECT * FROM sq1;

-- VIEW, not logged but TABLE is logged.
SELECT * FROM obj_type_v;

-- MATERIALIZED VIEW, logged.
SELECT * FROM obj_type_mv;

-- FUNCTION, logged.
SELECT test_func();
