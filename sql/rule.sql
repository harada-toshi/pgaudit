\! echo "pgaudit.config_file = '/tmp/config.conf'" >> ./tmp_check/data/postgresql.conf
\! rm ./tmp_check/tmp_check.log

\! cp sql/rule/rule-0.conf /tmp/config.conf
\! pg_ctl restart -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! sleep 3
\! psql contrib_regression -q -a < sql/rule/rule.sql
\! rm /tmp/config.conf

\! cp sql/rule/rule-1.conf /tmp/config.conf
\! pg_ctl restart -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! sleep 3
\! psql contrib_regression -q -a < sql/rule/rule.sql
\! rm /tmp/config.conf

\! cp sql/rule/rule-n.conf /tmp/config.conf
\! pg_ctl restart -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! sleep 3
\! psql contrib_regression -q -a < sql/rule/rule.sql
\! rm /tmp/config.conf

\! grep "AUDIT:" ./tmp_check/tmp_check.log > results/rule.out

