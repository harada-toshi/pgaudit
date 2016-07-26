/*
 * pgaudit.h
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * This is an internal header file for pgaudit*.c, not for user programs.
 *
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit.h
 */
#ifndef PGAUDIT_H
#define PGAUDIT_H
#include <string.h>
#include "postgres.h"
#include "lib/stringinfo.h"
#ifndef _SYS_SYSLOG_H
#include <syslog.h>
#endif

/*
 * ELOG() is a elog() but surpresses output logs to clients.
 *
 * 1. When the level is lesser than log_min_messages.
 * 	Surpress to call elog.
 * 	(Because elog() does not call emit_log_hook() in this case. )
 *
 * 2. When the level is greater than or equal to log_min_messages.
 * 	Call elog() with incliment of emitLogCalled.
 * 	Elog() calls emit_log_hook() before output logs to server, and the 
 * 	pgaudit_emit_log_hook sets the flag edata.output_to_client to OFF,
 * 	if emitLogCalled is positive.
 *  Then elog() does not outpuut log to client by the flag.
 *
 *  Note:
 *  Originaly, emitLogCalled was implemented for suppress the recursive 
 *  call of emit_log_hook().
 */

#define ELOG(level,...) {\
extern int log_min_messages;\
extern int emitLogCalled; \
    if (isOutPutELOG((level), log_min_messages)){\
        emitLogCalled++;\
        elog(level, __VA_ARGS__);\
        emitLogCalled--;\
    } \
}

/*
 * isOutPutELOG(level, min_m)
 * 	Determine to output or not to serverlog.
 *
 * 	This is true when level is grater than or equal to min_m(log_min_messages).
 *
 * Exception:
 * 1. LOG=15 
 * 	It should be bigger than ERROR=20 and lesser than FATAL=21 for serverlog. 
 * 	We took care about this.
 *
 * 2. COMMERROR=16
 * 	It should be bigger than ERROR=20 and lesser than FATAL=21 for serverlog. 
 * 	We ignore this, because we don't set COMMERROR to min_m or level neither.
 *
 */
#define isOutPutELOG(level, min_m) ( \
         (level==LOG) ? (FATAL>min_m): \
         (min_m==LOG) ? (level>ERROR): (level>=min_m))

/* error level for configlation deploy */
#define CONFNORMAL DEBUG1
#define CONFIGNORE INFO

/*
 * enum loggerType
 * type pgauditLogger
 *
 * 		paramators for logger.
 */
enum pgauditLoggerType {
    pgaudit__serverlog,		/* serverlog */
    pgaudit__syslog			/* syslog-compatible */
};

typedef struct pgauditLogger {
    enum pgauditLoggerType  	 logger;
    int	 	 level;			/* elog( level, message ...); */
    char	*pathlog;
    int	 	 option;
    int	 	 logger_option;
    char	*ident;
    int	 	 facility;
    int	 	 priority;		/* syslog(priority, message ...); */
    int	 	 maxlength;
} pgauditLogger;

/*
 * enum pgauditItem
 * type pgauditPrintIndex
 * enum pgauditOperator
 * type pgauditRighthand
 * type pgauditFilter
 *
 *		paramators for evaluator.
 */
enum pgauditItem {
    null_item_i		=0,		/* list stopper */
    format_text_i,			/* format item */
    application_name_i,		/* print & filter item */
    command_result_i,		/* print & filter item */
    command_text_i,			/* print item */
    command_parameter_i,	/* print item */
    connection_message_i,	/* print item */
    database_i,				/* print & filter item */
    class_i,				/* print & filter item */
    command_tag_i,			/* print & filter item */
    object_type_i,			/* print & filter item */
    object_id_i,			/* print & filter item */
    pid_i,
    remote_host_i,			/* print & filter item */
    remote_port_i,			/* print item */
    user_i,					/* print & filter item */
    statement_id_i,			/* print item */
    sub_statement_id_i,		/* print & filter item */
    timestamp_i,			/* print & filter item */
    current_user_i,			/* print & filter item */
    virtual_xid_i			/* print item */
};

enum pgauditOperator {
    operator_equal	= false,  	/* true^false=true, false^false=false */
    operator_notequal = true	/* true^true=false, false^true=true */
};

typedef union {
    char	 			*literal;	/* Sequense of Name delimited by " " */
    char				**roster;	/* Names in argv style terminated by ""*/
    int		 			*numbers;	/* Sequense of Number terminated by -1 */
}   pgauditRighthand;

typedef struct pgauditPrintIndex {
    enum pgauditItem	 item;	/* print pgauditDataIndex[item]->data */
    char				*text;	/* print before item */
} pgauditPrintIndex;

typedef struct pgauditFilter {
    enum pgauditItem	 lefthand;
    enum pgauditOperator operator;
    pgauditRighthand	 righthand;
    struct pgauditFilter *next;
}   pgauditFilter;

/*
 * type pgauditRule
 *
 * 		pgaudit rule structure.
 */
typedef struct pgauditRule {
    pgauditFilter		*filters;	/* chane of Filter structures */
    char				*format;	/* plane text of input literal */
    pgauditPrintIndex   *printIndex;/* sequence of printIndex terminated by null_item */
    struct pgauditRule	*next;		/* chane of Rule structures */
}   pgauditRule;

/*
 * enum pgauditStringType
 */
enum pgauditStringType {
    fix		= 0,
    direct,
    flex
};
    

/*
 *	pgauditDataIndex
 *		audit data index type.
 */
typedef struct pgauditDataIndex {
    const char 					name[24];
    const enum pgauditItem		item;
    enum pgauditStringType		type;
    union {
        char		   			*fix;			/* " name1 name2 " */
        char		   			*direct;		/* "name1" */
        StringInfoData			*flex;			/* " name1 name2 " */
    } data;
} pgauditDataIndex;


#define NULLSTRING (char*)pgauditNullString

#ifdef PGAUDIT_MAIN
char pgauditNullString[] = " ";

/*
 *  pgauditLoggerOption
 *  	Logger options to output
 */
pgauditLogger pgauditLoggerOption = {
    pgaudit__serverlog,
    LOG,
    "/dev/log",
    LOG_CONS|LOG_PID,
    0,
    "PGAUDIT",
    LOG_USER,
    LOG_WARNING,
    0
};
    
    
/*
 *	pgauditDataIndexes
 *		an audit data index list.
 *		each *(data.fix) and *(data.flex.data) must be a NULL, %,  or printable string.
 *		a string is blanc delimited words, start and end by blanc, such as follows:
 *			" name1 name2 ... nameX "
 */
char pgauditPcentData[4] = " % " ;

static char sqlState[6+3]	= " ";
static char processId[6+3] = " ";
static char remoteHost[256+3] = " ";
static char remotePort[6+3] = " ";
static char statementId[11+3] = " ";
static char substatementId[11+3] = " ";
#define FORMATTED_TS_LEN 128
static char formattedLogTime[FORMATTED_TS_LEN] = " ";
static char virtualXId[34] = " ";
static StringInfoData pgaudit_xStr[11];
#define VSTR(i) (char *)(&pgaudit_xStr[(i)])

pgauditDataIndex pgauditDataIndexes[] = { 
    { "null_item",			null_item_i,		fix,  { NULLSTRING } },
    { "format_text",		format_text_i,		fix,  { pgauditPcentData } },
    { "application_name",	application_name_i,	flex, { VSTR(0) } },
    { "command_result",		command_result_i,	fix,  { sqlState } },
    { "command_text",		command_text_i,		flex, { VSTR(1) } },
    { "command_parameter", 	command_parameter_i,flex, { VSTR(2) } },
    { "connection_message", connection_message_i, flex, { VSTR(3) } },
    { "database",			database_i,			flex, { VSTR(4) } },
    { "class",				class_i,			flex, { VSTR(5) } },
    { "command_tag",		command_tag_i,		flex, { VSTR(6) } },
    { "object_type",		object_type_i,		flex, { VSTR(7) } },
    { "object_id",			object_id_i,		flex, { VSTR(8) } },
    { "pid",				pid_i,				fix,  { processId } },
    { "remote_host",		remote_host_i,		fix,  { remoteHost } },
    { "remote_port",		remote_port_i,		fix,  { remotePort } },
    { "user",				user_i,				flex, { VSTR(9) } },
    { "statement_id",		statement_id_i,		fix,  { statementId } },
    { "sub_statement_id",	sub_statement_id_i,	fix,  { substatementId } },
    { "timestamp",			timestamp_i,		fix,  { formattedLogTime } },
    { "current_user",		current_user_i,		flex, { VSTR(10) } },
    { "virtual_xid",		virtual_xid_i,		fix,  { virtualXId } },
    { "null_item",			null_item_i,		fix,  { NULLSTRING } },
}; 

int	pgauditLogSecOfDay=0;

/*
 * chane root of pgauditRule(s).
 */
pgauditRule *pgauditRules = NULL;


#ifdef DEBUG
/*
 * Default Log format in DEBUG action.
 */
const pgauditPrintIndex pgauditDefaultPrintIndex[] = {
    { timestamp_i,			"PGAUDIT timestamp[" },
    { application_name_i, 	"],application_name[" },
    { command_result_i,		"],command_result[" },
    { command_parameter_i,	"],command_parameter[" },
    { connection_message_i,	"],connection_message[" },
    { database_i,			"],database[" },
    { class_i,				"],class[" },
    { command_tag_i,		"],command_tag[" },
    { object_type_i,		"],object_type[" },
    { object_id_i,			"],object_id[" },
    { pid_i,				"],pid[" },
    { remote_host_i,		"],remote_host[" },
    { remote_port_i,		"],remote_port[" },
    { user_i,				"],user[" },
    { statement_id_i,		"],statement_id[" },
    { sub_statement_id_i,	"],sub_statement_id[" },
    { current_user_i,		"],current_user[" },
    { virtual_xid_i,		"],virtual_xid[" },
    { command_text_i,		"],command_text[" },
    { null_item_i,			"]" }
};

#else

/*
 * Default Log format 
 */
const pgauditPrintIndex pgauditDefaultPrintIndex[] = {
    { statement_id_i,       "AUDIT: SESSION," },
    { sub_statement_id_i,   "," },
    { class_i,              "," },
    { command_tag_i,        "," },
    { object_type_i,        "," },
    { object_id_i,          "," },
    { command_text_i,       "," },
    { null_item_i,          "" } 
};

#endif /* DEBUG */
#else

extern char 			pgauditNullString[];
extern pgauditLogger 	pgauditLoggerOption;
extern pgauditDataIndex pgauditDataIndexes[];
extern pgauditRule 		*pgauditRules;
extern int 				pgauditLogSecOfDay;

extern const pgauditPrintIndex pgauditDefaultPrintIndex[];


#endif /* !PGAUDIT_MAIN */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void pgaudit_executeRules(void);
void pgaudit_deploySyslogOption(char *name, char *literal);
void pgaudit_deployRules(char *name, char *operator, char *literal);
void pgaudit_parseConfiguration(char* filename);
void pgaudit_doOutput(char *message);
void pgaudit_set_options(char* name, char* value) ;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* PGAUDIT_H */
