\! cp sql/role/role.conf /tmp/config.conf
\! echo "pgaudit.config_file = '/tmp/config.conf'" >> ./tmp_check/data/postgresql.conf
\! rm ./tmp_check/tmp_check.log

\! pg_ctl -w restart -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! psql contrib_regression -q -a < sql/role/role.sql
\! rm /tmp/config.conf

\! grep "OBJECT" ./tmp_check/tmp_check.log > results/role.out

