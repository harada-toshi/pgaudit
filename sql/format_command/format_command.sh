#!/bin/sh
sleep 1
psql contrib_regression -q -a < sql/format_command/format_command.sql
sleep 1
grep "AUDIT:" ./tmp_check/tmp_check.log > results/format_command.out
rm /tmp/config.conf
