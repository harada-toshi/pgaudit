#!/bin/sh
sleep 1
psql contrib_regression -q -a < sql/format_object/format_object.sql
sleep 1
grep "AUDIT:" ./tmp_check/tmp_check.log > results/format_object.out
rm /tmp/config.conf
