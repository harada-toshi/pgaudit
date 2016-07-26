#!/bin/sh
psql contrib_regression -c "SELECT 'ABC'"
grep "AUDIT:" ./tmp_check/tmp_check.log > results/format_host_port.out
