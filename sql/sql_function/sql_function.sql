CREATE OR REPLACE FUNCTION test_func(l integer) RETURNS integer AS $$
DECLARE
i integer;
j integer;
k integer;
BEGIN
    k := 0;
    FOR i IN 1..l LOOP
        SELECT power(i, 2) INTO j ;
        k := k + j;
    END LOOP;
    return k;
END;
$$ LANGUAGE plpgsql;

SELECT test_func(5);

DROP FUNCTION test_func(l integer);

DO $$
DECLARE
i integer;
j integer;
k integer;
BEGIN
    k := 0;
    FOR i IN 1..5 LOOP
        SELECT power(i, 2) INTO j ;
        k := k + j;
    END LOOP;
END$$;

