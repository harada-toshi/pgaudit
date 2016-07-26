\! cp sql/filter_database/filter_database.conf /tmp/config.conf
\! echo "pgaudit.config_file = '/tmp/config.conf'" >> ./tmp_check/data/postgresql.conf
\! rm ./tmp_check/tmp_check.log

\! pg_ctl restart -w -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! sh sql/filter_database/filter_database.sh

\! rm /tmp/config.conf

\! grep "AUDIT:" ./tmp_check/tmp_check.log > results/filter_database.out

