#####################################################################
# Makefile
#
# Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
#
#####################################################################
# contrib/pg_audit/Makefile

LFLAGS = -i
YFLAGS = -d
MODULE_big = pgaudit
OBJS = pgaudit.o  pgaudit_parseConfigurations.o pgaudit_parse.o pgaudit_scan.o pgaudit_deployConfigurations.o pgaudit_executeRules.o pgaudit_syslog.o  pgaudit_data.o $(WIN32RES)

EXTENSION = pgaudit
DATA = pgaudit--1.0.sql
PGFILEDESC = "pgAudit - An audit logging extension for PostgreSQL"

REGRESS = pgaudit config config-error log_catalog log_parameter log_statement_once role rule format_application_name format_database_user format_pid_vxid format_host_port format_command format_class format_object format_statement_id filter_database filter_user filter_class filter_object_id filter_timestamp transaction sql_dml sql_function sql_ddl sql_misc
#REGRESS = pgaudit
#REGRESS_OPTS = --temp-config=$(top_srcdir)/contrib/pgaudit/pgaudit.conf
REGRESS_OPTS = --temp-config=./pgaudit.conf --temp-instance=./tmp_check

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pgaudit
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
