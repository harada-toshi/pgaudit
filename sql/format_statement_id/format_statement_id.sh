#!/bin/sh
sleep 1
psql contrib_regression -q -a < sql/format_statement_id/format_statement_id.sql
sleep 1
grep "AUDIT:" ./tmp_check/tmp_check.log > results/format_statement_id.out
rm /tmp/config.conf
