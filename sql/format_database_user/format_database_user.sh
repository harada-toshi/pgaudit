#!/bin/sh
unset PGAPPNAME
createuser foo_user
createdb foo
psql -U foo_user foo -c "SELECT 1"
dropdb foo
dropuser foo_user
