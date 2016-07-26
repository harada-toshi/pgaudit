#!/bin/sh
unset PGAPPNAME
createdb foo
psql foo -c "SELECT 1"
dropdb foo
cat ./tmp_check/tmp_check.log | egrep "AUDIT:" > results/format_application_name.out
