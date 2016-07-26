\! cp sql/sql_ddl/sql_ddl.conf /tmp/config.conf
\! echo "pgaudit.config_file = '/tmp/config.conf'" >> ./tmp_check/data/postgresql.conf
\! rm ./tmp_check/tmp_check.log
\! pg_ctl restart -w -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! psql contrib_regression -q -a < sql/sql_ddl/sql_ddl.sql
\! rm /tmp/config.conf
\! grep "AUDIT:" ./tmp_check/tmp_check.log > results/sql_ddl.out

