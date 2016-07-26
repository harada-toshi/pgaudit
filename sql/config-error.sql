\! cp sql/config-error/regress.conf /tmp/config.conf
\! echo "pgaudit.config_file = '/tmp/config.conf'" >> ./tmp_check/data/postgresql.conf
\! rm ./tmp_check/tmp_check.log
\! pg_ctl restart -w -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! sleep 1
\! rm /tmp/config.conf
\! psql contrib_regression -q -a < sql/config-error/config-error.sql
\! egrep '(WARNING|pgaudit)' ./tmp_check/tmp_check.log > results/config-error.out

