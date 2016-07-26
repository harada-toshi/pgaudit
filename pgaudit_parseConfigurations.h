/*
 * pgaudit_parseConfigurations.h
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit_parseConfigurations.h
 */

#ifndef PGAUDIT_PARSECONFIGURATIONS_H
#define PGAUDIT_PARSECONFIGURATIONS_H

/* extern functions */
extern void pgaudit_initConfiguration(void);
extern void pgaudit_parseConfiguration(char* filename);

extern void pgaudit_set_options(char* name, char* value);
extern void pgaudit_set_output_literal(char* name, char* value);
extern void pgaudit_set_output_integer(char* name, char* value);
extern void pgaudit_set_output_boolean(char* name, char* value);
extern void pgaudit_set_format(char* value);

/* parser extern*/
extern int yyparse(void);
extern void yyset_in(FILE* in);

/* options extern */
extern int auditLogBitmap;
extern bool auditLogCatalog;
extern bool auditLogParameter;
extern bool auditLogStatementOnce;
extern char* auditRole;
#endif
