BEGIN;
PREPARE prep_dx AS SELECT * FROM pg_extension WHERE extname = $1 AND extversion = $2;
EXECUTE prep_dx ('plpgsql','1.0');
DEALLOCATE PREPARE prep_dx;
COMMIT;
