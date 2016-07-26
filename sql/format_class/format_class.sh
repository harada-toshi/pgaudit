#!/bin/sh
sleep 1
psql contrib_regression -q -a < sql/format_class/format_class.sql
sleep 1
grep "AUDIT:" ./tmp_check/tmp_check.log > results/format_class.out
rm /tmp/config.conf
