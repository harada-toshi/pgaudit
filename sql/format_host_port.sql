\! echo "pgaudit.config_file = '/tmp/config.conf'" >> ./tmp_check/data/postgresql.conf
\! echo "listen_addresses = 'localhost'" >> ./tmp_check/data/postgresql.conf
\! rm ./tmp_check/tmp_check.log
\! cp sql/format_host_port/format_host_port.conf /tmp/config.conf
\! pg_ctl restart -w -D ./tmp_check/data -l ./tmp_check/tmp_check.log
\! sleep 1
\! rm /tmp/config.conf
\! sh sql/format_host_port/format_host_port.sh

