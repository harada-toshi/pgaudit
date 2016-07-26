\! echo "pgaudit.config_file = '/tmp/config.conf'" >> ./tmp_check/data/postgresql.conf
\! rm ./tmp_check/tmp_check.log

\! cp sql/format_pid_vxid/format_pid_vxid.conf /tmp/config.conf
\! pg_ctl restart -w -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! psql contrib_regression -q -a < sql/format_pid_vxid/format_pid_vxid.sql
\! rm /tmp/config.conf

\! grep "AUDIT:" ./tmp_check/tmp_check.log | sed 's/[0-9]\+/X/g'> results/format_pid_vxid.out

