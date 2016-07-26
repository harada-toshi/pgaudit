/*
 * pgaudit_syslog.h
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit_syslog.h
 */
#ifndef _PGAUDIT_SYSLOG_H_
#define _PGAUDIT_SYSLOG_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
void pgaudit_openlog(const char *ident, int logstat, int logfac,const char *socketpath);
void pgaudit_syslog(int pri,const char *format,...);
void pgaudit_closelog(void);
int  pgaudit_setlogmask(int pmask);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _PGAUDIT_SYSLOG_H_ */
