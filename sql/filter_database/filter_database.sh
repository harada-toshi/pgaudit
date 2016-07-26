#!/bin/sh
createuser foo_user
createuser bar_user
createdb foo
createdb bar
psql -U foo_user foo -c "SELECT 1"
psql -U foo_user bar -c "SELECT 2"
dropdb foo
dropdb bar
dropuser foo_user
dropuser bar_user
