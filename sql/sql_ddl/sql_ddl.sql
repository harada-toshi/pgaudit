CREATE TABLE foo (
    id int,
    data text,
    CONSTRAINT foo_id_key PRIMARY KEY (id)
);

CREATE TABLE bar AS SELECT * FROM foo;

ALTER TABLE foo RENAME TO baz;

DROP TABLE bar;
DROP TABLE baz;

