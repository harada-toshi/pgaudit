\! cp sql/format_object/format_object.conf /tmp/config.conf
\! echo "pgaudit.config_file = '/tmp/config.conf'" >> ./tmp_check/data/postgresql.conf
\! rm ./tmp_check/tmp_check.log
\! pg_ctl -w restart -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! sh sql/format_object/format_object.sh
