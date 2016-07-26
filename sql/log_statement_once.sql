\! cp sql/log_statement_once/log_statement_once_default.conf /tmp/config.conf
\! echo "pgaudit.config_file = '/tmp/config.conf'" >> ./tmp_check/data/postgresql.conf
\! rm ./tmp_check/tmp_check.log

\! pg_ctl restart -w -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! psql contrib_regression -q -a < sql/log_statement_once/log_statement_once.sql
\! rm /tmp/config.conf

\! cp sql/log_statement_once/log_statement_once_on.conf /tmp/config.conf
\! pg_ctl restart -w -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! psql contrib_regression -q -a < sql/log_statement_once/log_statement_once.sql
\! rm /tmp/config.conf

\! cp sql/log_statement_once/log_statement_once_off.conf /tmp/config.conf
\! pg_ctl restart -w -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! psql contrib_regression -q -a < sql/log_statement_once/log_statement_once.sql
\! rm /tmp/config.conf

\! grep "OBJECT" ./tmp_check/tmp_check.log > results/log_statement_once.out

