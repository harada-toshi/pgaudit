/*
 * pgaudit.c
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*------------------------------------------------------------------------------
 * An audit logging extension for PostgreSQL. Provides detailed logging classes,
 * object level logging, and fully-qualified object names for all DML and DDL
 * statements where possible (See pgaudit.sgml for details).
 *
 * IDENTIFICATION
 *          contrib/pgaudit/pgaudit.c
 *------------------------------------------------------------------------------
 */
#include "postgres.h"
#include "pgtime.h"

#include "access/htup_details.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_class.h"
#include "catalog/namespace.h"
#include "commands/dbcommands.h"
#include "catalog/pg_proc.h"
#include "commands/event_trigger.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "libpq/auth.h"
#include "nodes/nodes.h"
#include "tcop/utility.h"
#include "tcop/deparse_utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"

#include "storage/proc.h"
#include "pgaudit.h"

PG_MODULE_MAGIC;

void _PG_init(void);

PG_FUNCTION_INFO_V1(pgaudit_ddl_command_end);
PG_FUNCTION_INFO_V1(pgaudit_sql_drop);

/*
 * Debug: function trace
 */
static bool isStartTrace = false;
static int z=1;
static char Z[1000];
#define PGA_FUNCTION_TRACE(str) { \
    if (!strcmp((str),"IN-")) z++; \
    memset(Z,' ',z*2);\
    Z[z*2+1]='\0';\
    if (isStartTrace) ELOG(DEBUG3, \
        "PGA_FUNCTION_TRACE:pgaudit.c:%s:%s%s",(str), Z, __func__); \
    if (strcmp((str),"IN-")) z--; \
    if (z>50) z=10; \
}

/*
 * Log Classes
 *
 * pgAudit categorizes actions into classes (eg: DDL, FUNCTION calls, READ
 * queries, WRITE queries).  A GUC is provided for the administrator to
 * configure which class (or classes) of actions to include in the
 * audit log.  We track the currently active set of classes using
 * auditLogBitmap.
 */

/* Bits within auditLogBitmap, defines the classes we understand */
#define LOG_DDL         (1 << 0)    /* CREATE/DROP/ALTER objects */
#define LOG_FUNCTION    (1 << 1)    /* Functions and DO blocks */
#define LOG_MISC        (1 << 2)    /* Statements not covered */
#define LOG_READ        (1 << 3)    /* SELECTs */
#define LOG_ROLE        (1 << 4)    /* GRANT/REVOKE, CREATE/ALTER/DROP ROLE */
#define LOG_WRITE       (1 << 5)    /* INSERT, UPDATE, DELETE, TRUNCATE */
#define LOG_NONE        0               /* nothing */
#define LOG_ALL         (0xFFFFFFFF)    /* All */

/*
 * String constants for log classes - used when processing tokens in the
 * pgaudit.log GUC.
 */
#define CLASS_DDL       "DDL"
#define CLASS_FUNCTION  "FUNCTION"
#define CLASS_MISC      "MISC"
#define CLASS_READ      "READ"
#define CLASS_ROLE      "ROLE"
#define CLASS_WRITE     "WRITE"
#define CLASS_NONE      "NONE"
#define CLASS_ALL       "ALL"

/*
 * GUC variables.
 *
 * pgaudit_deployConfigulations.c::pgaudit_set_options() sets these values.
 */

/*
 *  variable for pgaudit.log, which defines the classes to log. 
 *  
 * 	char *auditLog = NULL;
 */

/*
 * variable for pgaudit.file	2016.03
 * 
 * Administrators can specify the path to the configuration file Auditors
 * manages. Auditors can choose the setting following, and more.
 */
char *config_file = NULL;

/*
 * variables for pgaudit.option.log_catalog
 *
 * Auditors can choose to NOT log queries when all relations used in
 * the query are in pg_catalog.  Interactive sessions (eg: psql) can cause
 * a lot of noise in the logs which might be uninteresting.
 */
bool auditLogCatalog = true;

/*
 * variable for pgaudit.option.log_level
 *
 * Auditors can choose which log level the audit log is to be logged
 * at.  The default level is LOG, which goes into the server log but does
 * not go to the client.  Set to NOTICE in the regression tests.
 */
char *auditLogLevelString = NULL;
int auditLogLevel = LOG;

/*
 * variable for pgaudit.option.log_parameter
 *
 * Auditors can choose if parameters passed into a statement are
 * included in the audit log.
 */
bool auditLogParameter = false;

/*
 * GUC variable for pgaudit.log_relation
 *
 * Administrators can choose, in SESSION logging, to log each relation involved
 * in READ/WRITE class queries.  By default, SESSION logs include the query but
 * do not have a log entry for each relation.
 */

/*
 * variable for pgaudit.option.log_statement_once
 *
 * Auditors can choose to have the statement run logged only once instead
 * of on every line.  By default, the statement is repeated on every line of
 * the audit log to facilitate searching, but this can cause the log to be
 * unnecessairly bloated in some environments.
 */
bool auditLogStatementOnce = false;

/*
 * variable for pgaudit.option.role
 *
 * Auditors can choose which role to base OBJECT auditing off of.
 * Object-level auditing uses the privileges which are granted to this role to
 * determine if a statement should be logged.
 */
char *auditRole = NULL;

/*
 * String constants for the audit log fields.
 */

/*
 * Audit type, which is responsbile for the log message
 */
#define AUDIT_TYPE_OBJECT   "OBJECT"
#define AUDIT_TYPE_SESSION  "SESSION"

/*
 * Command, used for SELECT/DML and function calls.
 *
 * We hook into the executor, but we do not have access to the parsetree there.
 * Therefore we can't simply call CreateCommandTag() to get the command and have
 * to build it ourselves based on what information we do have.
 *
 * These should be updated if new commands are added to what the exectuor
 * currently handles.  Note that most of the interesting commands do not go
 * through the executor but rather ProcessUtility, where we have the parsetree.
 */
#define COMMAND_SELECT      "SELECT"
#define COMMAND_INSERT      "INSERT"
#define COMMAND_UPDATE      "UPDATE"
#define COMMAND_DELETE      "DELETE"
#define COMMAND_EXECUTE     "EXECUTE"
#define COMMAND_UNKNOWN     "UNKNOWN"

/* 2016.03
 * Command used for Connection/Utility calls.
 *
 * We handle these by Message in emit_log_hook.
 */
#define COMMAND_CONNECT     "CONNECT"
#define COMMAND_SYSTEM      "SYSTEM"
#define COMMAND_BACKUP      "BACKUP"

/* 2016.03
 * Message, used for Connection/Utility calls.
 */
#define MESSAGE_RECEIVED    "received"
#define MESSAGE_AUTHORIZED  "authorized"
#define MESSAGE_DISCONNECTED "disconnected"
#define MESSAGE_READY       "ready"
#define MESSAGE_NORMALENDED "normal ended"
#define MESSAGE_INTERRUPTED "interrupted"


/*
 * Object type, used for SELECT/DML statements and function calls.
 *
 * For relation objects, this is essentially relkind (though we do not have
 * access to a function which will just return a string given a relkind;
 * getRelationTypeDescription() comes close but is not public currently).
 *
 * We also handle functions, so it isn't quite as simple as just relkind.
 *
 * This should be kept consistent with what is returned from
 * pg_event_trigger_ddl_commands(), as that's what we use for DDL.
 */
#define OBJECT_TYPE_TABLE           "TABLE"
#define OBJECT_TYPE_INDEX           "INDEX"
#define OBJECT_TYPE_SEQUENCE        "SEQUENCE"
#define OBJECT_TYPE_TOASTVALUE      "TOAST TABLE"
#define OBJECT_TYPE_VIEW            "VIEW"
#define OBJECT_TYPE_MATVIEW         "MATERIALIZED VIEW"
#define OBJECT_TYPE_COMPOSITE_TYPE  "COMPOSITE TYPE"
#define OBJECT_TYPE_FOREIGN_TABLE   "FOREIGN TABLE"
#define OBJECT_TYPE_FUNCTION        "FUNCTION"

#define OBJECT_TYPE_UNKNOWN         "UNKNOWN"

/*
 * String constants for testing role commands.  Rename and drop role statements
 * are assigned the nodeTag T_RenameStmt and T_DropStmt respectively.  This is
 * not very useful for classification, so we resort to comparing strings
 * against the result of CreateCommandTag(parsetree).
 */
#define COMMAND_ALTER_ROLE          "ALTER ROLE"
#define COMMAND_DROP_ROLE           "DROP ROLE"
#define COMMAND_GRANT               "GRANT"
#define COMMAND_REVOKE              "REVOKE"


/*
 * String constants used for redacting text after the password token in
 * CREATE/ALTER ROLE commands.
 */
#define TOKEN_PASSWORD             "password"
#define TOKEN_REDACTED             "<REDACTED>"

/*
 * An AuditEvent represents an operation that potentially affects a single
 * object.  If a statement affects multiple objects then multiple AuditEvents
 * are created to represent them.
 */
typedef struct
{
    int64 statementId;          /* Simple counter */
    int64 substatementId;       /* Simple counter */

    LogStmtLevel logStmtLevel;  /* From GetCommandLogLevel when possible,
                                   generated when not. */
    NodeTag commandTag;         /* same here */
    const char *command;        /* same here */
    const char *objectType;     /* From event trigger when possible,
                                   generated when not. */
    char *objectName;           /* Fully qualified object identification */
    const char *commandText;    /* sourceText / queryString */
    ParamListInfo paramList;    /* QueryDesc/ProcessUtility parameters */

    bool granted;               /* Audit role has object permissions? */
    bool logged;                /* Track if we have logged this event, used
                                   post-ProcessUtility to make sure we log */
    bool statementLogged;       /* Track if we have logged the statement */
} AuditEvent;

/*
 * A simple FIFO queue to keep track of the current stack of audit events.
 */
typedef struct AuditEventStackItem
{
    struct AuditEventStackItem *next;

    AuditEvent auditEvent;

    int64 stackId;

    MemoryContext contextAudit;
    MemoryContextCallback contextCallback;
} AuditEventStackItem;

AuditEventStackItem *auditEventStack = NULL;

/*
 * pgAudit runs queries of its own when using the event trigger system.
 *
 * Track when we are running a query and don't log it.
 */
static bool internalStatement = false;

/*
 * Track running total for statements and substatements and whether or not
 * anything has been logged since the current statement began.
 */
static int64 statementTotal = 0;
static int64 substatementTotal = 0;
static int64 stackTotal = 0;
static bool statementLogged = false;

/*------------------------------------------------------------------------------
 * SESSION AUDIT LOGGING : flag, data and functions
 */

/*
 *	A Memory Context for pgaudit 2016.03
 *
 *	Permanent.
 *	The Memory in this context is allocated at _PG_init(postmaster) and used 
 *	under the hooks(postmaster & backends)
 */
MemoryContext contextAuditPermanent;

/*
 * item logging fields.	2016.03
 *
 * Max length for a timestamp character string.
 */
#define FORMATTED_TS_LEN 128

/*
 * Flag to prevent the recursive call of emit_log_hook.
 */
/* static */ int  emitLogCalled=0;

/*
 * Flag that displays the data collection situation for pgaudit_ExecutorEnd_hook
 */
static bool keptDMLLogData = false;

/*
 * GUC Flags that should be True always in order to hook the eventsi at 
 * emit_log_hook.
 */
extern bool Log_connections;
extern bool Log_disconnections;
extern bool log_replication_commands;
/*
 * Buckup Flags. The value will set to edata at the event at emit_log_hook.
 */
static bool saveLogConnections = true;
static bool saveLogDisconnections = true;
static bool saveLogReplicationCommands = true;
/*
 * Flags that displays inner status og pgaudit.
 */
static bool isPGinitDone = false;
static bool utilityStatement = false;
static bool executorStart = false;

/*
 * Messageid 2016.03
 *
 * message-ids that the pgaudit_emit_log_hook() handles.
 */
#define MsgId_Connection1 \
"connection received: host=%s port=%s"
#define MsgId_Connection2 \
"connection authorized: user=%s database=%s"
#define MsgId_DisConnect \
"disconnection: session time: %d:%02d:%02d.%03d user=%s database=%s host=%s%s%s"
#define MsgId_ShutDown1 \
"database system was shut down at %s"
#define MsgId_ShutDown2 \
"database system was shut down in recovery at %s"
#define MsgId_Interrupt1 \
"database system was interrupted while in recovery at %s"
#define MsgId_Interrrupt2 \
"database system was interrupted while in recovery at log time %s"
#define MsgId_Interrrupt3 \
"database system was interrupted; last known up at %s"
#define MsgId_Redy \
"database system is ready to accept connections"
#define MsgId_Replication \
"received replication command: BASE_BACKUP"
#define MsgId_NewTimeline \
"selected new timeline ID: %u"
#define MsgId_PC \
"parameter \"%s\" changed to \"%s\""

/*
 *	Message 2016.03
 *
 *	Part of the Messages corresponding to the locale. Pgaudit_emit_log_hook() 
 *	recognizes an event by right truncation of an actual message.
 */
#define PGAUDIT_MSG_MATCH_MAX 200
static char 		   
Msg_Connection1[ PGAUDIT_MSG_MATCH_MAX ],
Msg_Connection2[ PGAUDIT_MSG_MATCH_MAX ],
Msg_DisConnect[  PGAUDIT_MSG_MATCH_MAX ],
Msg_ShutDown1[   PGAUDIT_MSG_MATCH_MAX ],
Msg_ShutDown2[   PGAUDIT_MSG_MATCH_MAX ],
Msg_Interrupt1[  PGAUDIT_MSG_MATCH_MAX ],
Msg_Interrrupt2[ PGAUDIT_MSG_MATCH_MAX ],
Msg_Interrrupt3[ PGAUDIT_MSG_MATCH_MAX ],
Msg_Redy[        PGAUDIT_MSG_MATCH_MAX ],
Msg_Replication[ PGAUDIT_MSG_MATCH_MAX ],
Msg_NewTimeline[ PGAUDIT_MSG_MATCH_MAX ],
Msg_PC_LC[       PGAUDIT_MSG_MATCH_MAX ],
Msg_PC_LD[		 PGAUDIT_MSG_MATCH_MAX ],
Msg_PC_RP[		 PGAUDIT_MSG_MATCH_MAX ];

/*
 * initMessages		2016.03
 *   ->msgidToMsg
 *   ->msgidToMsgWithStr
 *
 * Apply the locale to the messages those emit_log_hook() handles.
 */

/* Convert messageid to pattern mach string with the locale.*/
static void 
pgaudit_msgidToMsg(char *msgid, char *to)
{
    char *x = dgettext( 0, msgid );
    int   i =0;

    /* copy till an escape. */
    for (i=0; i<(PGAUDIT_MSG_MATCH_MAX-1); i++)
    {
        if ( x[i] == '%' || x[i] == '\0' )
            break;
        to[i] = x[i];
    }
    to[i] = '\0';
}

/*
 * Convert messageid to pattern mach string with the locale, 
 * and embeds a str to the message.
 */
static void 
pgaudit_msgidToMsgWithStr(char *msgid, char *to, char *str)
{
    char  y[PGAUDIT_MSG_MATCH_MAX];
    char *x = dgettext( 0, msgid );
    int   i =0;

    /* embeds a str to the message. */
    strncpy(y, x, (PGAUDIT_MSG_MATCH_MAX-strlen(str)-1));
    sprintf(to, y, str, "%s");

    /* avoid the remaining escapes. */
    for (i=0; i<(PGAUDIT_MSG_MATCH_MAX-1); i++)
        if ( to[i] == '%' || to[i] == '\0' )
            break;
    to[i] = '\0';
}

static void 
pgaudit_initMessages()
{
    /* CONNECTION levael Messages */
    pgaudit_msgidToMsg( MsgId_Connection1,	Msg_Connection1 ); 
    pgaudit_msgidToMsg( MsgId_Connection2,	Msg_Connection2 ); 
    pgaudit_msgidToMsg( MsgId_DisConnect, 	Msg_DisConnect ); 
    pgaudit_msgidToMsg( MsgId_ShutDown1,	Msg_ShutDown1 ); 
    pgaudit_msgidToMsg( MsgId_ShutDown2,	Msg_ShutDown2 ); 
    pgaudit_msgidToMsg( MsgId_Interrupt1,	Msg_Interrupt1 ); 
    pgaudit_msgidToMsg( MsgId_Interrrupt2,	Msg_Interrrupt2 ); 
    pgaudit_msgidToMsg( MsgId_Interrrupt3,	Msg_Interrrupt3 ); 
    pgaudit_msgidToMsg( MsgId_Redy,			Msg_Redy ); 
    pgaudit_msgidToMsg( MsgId_Replication,	Msg_Replication ); 
    pgaudit_msgidToMsg( MsgId_NewTimeline,	Msg_NewTimeline ); 

    /* GUC Changed */
    pgaudit_msgidToMsgWithStr(MsgId_PC, Msg_PC_LC, "log_connections");
    pgaudit_msgidToMsgWithStr(MsgId_PC, Msg_PC_LD, "log_disconnections");
    pgaudit_msgidToMsgWithStr(MsgId_PC, Msg_PC_RP, "log_replication_commands");

    ELOG(DEBUG3, "Msg_PC_LC=[%s]", Msg_PC_LC);
    ELOG(DEBUG3, "Msg_PC_LD=[%s]", Msg_PC_LD);
    ELOG(DEBUG3, "Msg_PC_RP=[%s]", Msg_PC_RP);
}

/*
 * initItems	2016.03
 *
 *	initialise the item logging fields.
 */
static void
pgaudit_initItems(bool isAll)
{
    MemoryContext contextOld;
    static bool isInitStringInfo = true;
    pgauditDataIndex *index = pgauditDataIndexes;
    int i=0;

PGA_FUNCTION_TRACE("IN-");
    contextOld = MemoryContextSwitchTo(contextAuditPermanent);

    /* init StringInfo */
    if (isInitStringInfo) 
    {
        for (i=application_name_i; i<=virtual_xid_i; i++)
            if (index[i].type)
            	initStringInfo(index[i].data.flex);

    }

    /* All Clear */
    for (i=application_name_i; i<=virtual_xid_i; i++)
        switch (i)
        {
        case null_item_i:
        case format_text_i:
            /* use default always */
            break;
        case command_result_i:
            /* default of command_result is "00000" */
            strcpy(index[i].data.fix, " 00000 ");
            break;
        case current_user_i:
            if (isInitStringInfo)
            	break;
        case application_name_i:
        case database_i:
        case pid_i:
        case remote_host_i:
        case remote_port_i:
        case user_i:
            if (!isAll)
            	break;
        default:
            switch (index[i].type)
            {
            case fix:
            	strcpy(index[i].data.fix, pgauditNullString);
            	break;
            case flex:
            	resetStringInfo(index[i].data.flex);
            	appendStringInfoCharMacro(index[i].data.flex, ' ');
            	break;
            case direct:
            default:
            	index[i].data.fix = (char*) pgauditNullString;
            	break;
            }
            break;
        }

    isInitStringInfo = false; 
    
    MemoryContextSwitchTo(contextOld);
PGA_FUNCTION_TRACE("OUT");
}
/*
 * pgaudit_setTimestamps 2015.03
 *
 *  set a timestamp(to print) and seconds of a day(to ievaluate).
 */
static void
pgaudit_setTimestamps(void)
{
    pgauditDataIndex *x = &pgauditDataIndexes[timestamp_i];
    struct timeval tv;
    pg_time_t	stamp_time;
    struct pg_tm	*pg_time;

    /* get the current time */
    gettimeofday(&tv, NULL);
    stamp_time = (pg_time_t) tv.tv_sec;
    
    /* set the output string */
    pg_time = pg_localtime(&stamp_time, log_timezone);
    pg_strftime(x->data.fix, FORMATTED_TS_LEN, " %Y-%m-%d %H:%M:%S     %Z ", pg_time);

    /* set the filter value */
    pgauditLogSecOfDay = (pg_time->tm_hour*60*60) + (pg_time->tm_min*60) + pg_time->tm_sec;
}

/*
 * set a text to the item logging field.
 */
static void pgaudit_setTextToField(enum pgauditItem item, char *text, bool isClear)
{
    MemoryContext contextOld;
    pgauditDataIndex *x=&pgauditDataIndexes[item];

    if ( x->type == flex )
    {
        contextOld = MemoryContextSwitchTo(contextAuditPermanent);

        if ( isClear )
        {
            resetStringInfo(x->data.flex); 
            appendStringInfoCharMacro(x->data.flex, ' ');
        }

        if( ( text ) && ( *text != '\0' ) )
        {
            /* set txt to the logging field. */
            appendStringInfoString(x->data.flex, text);
            appendStringInfoCharMacro(x->data.flex, ' ');
        }

        MemoryContextSwitchTo(contextOld); 
    }
    else
    {
        char *to = x->data.fix;

        if ( isClear )
            strcpy(to, " ");

        if( ( text ) && ( *text != '\0' ) )
        {
            while ( *to != '\0' ) to++;
            sprintf(to, "%s ", text);
        }
    }
}

static void
set_process_id(void)
{
    pgauditDataIndex *x=&pgauditDataIndexes[pid_i];

PGA_FUNCTION_TRACE("IN-");
    sprintf( x->data.fix, " %d ", MyProcPid );
PGA_FUNCTION_TRACE("OUT");
}

static void
set_statement_id(void)
{
    pgauditDataIndex *x=&pgauditDataIndexes[statement_id_i];

PGA_FUNCTION_TRACE("IN-");
    ELOG(DEBUG3, "statementTotal=[[%ld]]", statementTotal);
    sprintf( x->data.fix, " %ld ", statementTotal);
    ELOG(DEBUG3, "x[statement_id_i].data.fix=[[%s]]", x[statement_id_i].data.fix);
PGA_FUNCTION_TRACE("OUT");
}

static void
set_substatement_id(void)
{
    pgauditDataIndex *x=&pgauditDataIndexes[sub_statement_id_i];

PGA_FUNCTION_TRACE("IN-");
    ELOG(DEBUG3, "substatementTotal=[[%ld]]", substatementTotal);
    sprintf( x->data.fix, " %ld ", substatementTotal);
    ELOG(DEBUG3, "x[sub_statement_id_i].data.fix=[[%s]]", x[sub_statement_id_i].data.fix);
PGA_FUNCTION_TRACE("OUT");
}

static void
set_virtual_x_id(void)
{
    pgauditDataIndex *x=&pgauditDataIndexes[virtual_xid_i];

PGA_FUNCTION_TRACE("IN-");
    if( ( MyProc ) && (MyProc->backendId) && (MyProc->lxid) )
        sprintf(x->data.fix, " %d/%u ", MyProc->backendId, MyProc->lxid);
    else
        sprintf(x->data.fix, "%s", " ");
PGA_FUNCTION_TRACE("OUT");
}

static void
set_command_result(int sqlErrorCode)
{
    pgauditDataIndex *x=&pgauditDataIndexes[command_result_i];

PGA_FUNCTION_TRACE("IN-");
    sprintf(x->data.fix, " %s ", unpack_sql_state(sqlErrorCode));
PGA_FUNCTION_TRACE("OUT");
}

static void
set_remote_host()
{
PGA_FUNCTION_TRACE("IN-");
    if ( MyProcPort ) 
        pgaudit_setTextToField(remote_host_i, MyProcPort->remote_host, true);
    else
        pgaudit_setTextToField(remote_host_i, NULL, true); 
PGA_FUNCTION_TRACE("OUT");
}

static void
set_remote_port()
{
PGA_FUNCTION_TRACE("IN-");
    if( MyProcPort ) 
        pgaudit_setTextToField(remote_port_i, MyProcPort->remote_port, true);
    else
        pgaudit_setTextToField(remote_port_i, NULL, true); 
PGA_FUNCTION_TRACE("OUT");
}

static void
set_database_name(void)
{
PGA_FUNCTION_TRACE("IN-");
    if( MyProcPort )
        pgaudit_setTextToField(database_i, MyProcPort->database_name, true);
    else
        pgaudit_setTextToField(database_i, NULL, true);
PGA_FUNCTION_TRACE("OUT");
}

static void
set_session_user_name()
{
PGA_FUNCTION_TRACE("IN-");
    if( MyProcPort )
        pgaudit_setTextToField(user_i, MyProcPort->user_name, true);
    else
        pgaudit_setTextToField(user_i, NULL, true);
PGA_FUNCTION_TRACE("OUT");
}

static void
set_interim_current_user()
{
PGA_FUNCTION_TRACE("IN-");
    if( MyProcPort )
        pgaudit_setTextToField(current_user_i, MyProcPort->user_name, true);
    else
        pgaudit_setTextToField(current_user_i, NULL, true);
PGA_FUNCTION_TRACE("OUT");
}


/*
 *  A debug function:
 *      output all items to ELOG, debug1.
 */
static void pgaudit_printData4debug(void)
{
    MemoryContext contextOld;
    static StringInfoData buf;
    static bool isFirst = true;
    pgauditDataIndex *x=pgauditDataIndexes;

    if (log_min_messages > DEBUG1)
        return;

    contextOld = MemoryContextSwitchTo(contextAuditPermanent);

    if ( isFirst )
        initStringInfo(&buf);
    else
        resetStringInfo(&buf);
    isFirst = false;

    appendStringInfoString(&buf, "HEADER[ AuditLog2 ],");
    appendStringInfo(&buf, "PID[%s],", 			x[pid_i].data.fix);
    appendStringInfo(&buf, "STATEMENTID[%s],", 	x[statement_id_i].data.fix);
    appendStringInfo(&buf, "SUBSTATEMENTID[%s],", x[sub_statement_id_i].data.fix);
    appendStringInfo(&buf, "TIMESTAMP[%s],", 	x[timestamp_i].data.fix);
    appendStringInfo(&buf, "SECOFDAY[%d],", 	pgauditLogSecOfDay);
    appendStringInfo(&buf, "DATABASE[%s],", 	x[database_i].data.flex->data);
    appendStringInfo(&buf, "CURRENTUSER[%s],", 	x[current_user_i].data.flex->data);
    appendStringInfo(&buf, "SESSIONUSER[%s],", 	x[user_i].data.flex->data);
    appendStringInfo(&buf, "CLASS[%s],", 		x[class_i].data.flex->data);
    appendStringInfo(&buf, "TAG[%s],", 			x[command_tag_i].data.flex->data);
    appendStringInfo(&buf, "OBJECTTYPE[%s],", 	x[object_type_i].data.flex->data);
    appendStringInfo(&buf, "OBJECTID[%s],", 	x[object_id_i].data.flex->data);
    appendStringInfo(&buf, "PROTOCOL[%s],", 	x[application_name_i].data.flex->data);
    appendStringInfo(&buf, "VIRTUALXID[%s],", 	x[virtual_xid_i].data.fix);
    appendStringInfo(&buf, "RESULT[%s],", 		x[command_result_i].data.fix);
    appendStringInfo(&buf, "TEXT[%s],", 		x[command_text_i].data.flex->data);
    appendStringInfo(&buf, "PARAMETER[%s],", 	x[command_parameter_i].data.flex->data);
    appendStringInfo(&buf, "REMOTEHOST[%s],", 	x[remote_host_i].data.fix);
    appendStringInfo(&buf, "REMOTEPORT[%s]", 	x[remote_port_i].data.fix);
    appendStringInfo(&buf, "MESSAGE[%s]", 		x[connection_message_i].data.flex->data);

    ELOG(DEBUG1,"%s", buf.data);
    MemoryContextSwitchTo(contextOld);
}


/*------------------------------------------------------------------------------
 * AUDIT LOG functions
 */

/*
 * Stack functions
 *
 * Audit events can go down to multiple levels so a stack is maintained to keep
 * track of them.
 */


/*
 * Respond to callbacks registered with MemoryContextRegisterResetCallback().
 * Removes the event(s) off the stack that have become obsolete once the
 * MemoryContext has been freed.  The callback should always be freeing the top
 * of the stack, but the code is tolerant of out-of-order callbacks.
 */
static void
stack_free(void *stackFree)
{
    AuditEventStackItem *nextItem = auditEventStack;

PGA_FUNCTION_TRACE("IN-");
    /* Only process if the stack contains items */
    while (nextItem != NULL)
    {
        /* Check if this item matches the item to be freed */
        if (nextItem == (AuditEventStackItem *) stackFree)
        {
            /* Move top of stack to the item after the freed item */
            auditEventStack = nextItem->next;

            /* If the stack is not empty */
            if (auditEventStack == NULL)
            {
                /*
                 * Reset internal statement to false.  Normally this will be
                 * reset but in case of an error it might be left set.
                 */
                internalStatement = false;

                /*
                 * Reset sub statement total so the next statement will start
                 * from 1.
                 */
                substatementTotal = 0;

                /*
                 * Reset statement logged so that next statement will be
                 * logged.
                 */
                statementLogged = false;
            }

            return;
        }

        nextItem = nextItem->next;
    }
PGA_FUNCTION_TRACE("OUT");
}

/*
 * Push a new audit event onto the stack and create a new memory context to
 * store it.
 */
static AuditEventStackItem *
stack_push()
{
    MemoryContext contextAudit;
    MemoryContext contextOld;
    AuditEventStackItem *stackItem;

PGA_FUNCTION_TRACE("IN-");
    /*
     * Create a new memory context to contain the stack item.  This will be
     * free'd on stack_pop, or by our callback when the parent context is
     * destroyed.
     */
    contextAudit = AllocSetContextCreate(CurrentMemoryContext,
                                         "pgaudit stack context",
                                         ALLOCSET_DEFAULT_MINSIZE,
                                         ALLOCSET_DEFAULT_INITSIZE,
                                         ALLOCSET_DEFAULT_MAXSIZE);

    /* Save the old context to switch back to at the end */
    contextOld = MemoryContextSwitchTo(contextAudit);

    /* Create our new stack item in our context */
    stackItem = palloc0(sizeof(AuditEventStackItem));
    stackItem->contextAudit = contextAudit;
    stackItem->stackId = ++stackTotal;

    /*
     * Setup a callback in case an error happens.  stack_free() will truncate
     * the stack at this item.
     */
    stackItem->contextCallback.func = stack_free;
    stackItem->contextCallback.arg = (void *) stackItem;
    MemoryContextRegisterResetCallback(contextAudit,
                                       &stackItem->contextCallback);

    /* Push new item onto the stack */
    if (auditEventStack != NULL)
        stackItem->next = auditEventStack;
    else
        stackItem->next = NULL;

    auditEventStack = stackItem;

    MemoryContextSwitchTo(contextOld);

PGA_FUNCTION_TRACE("OUT");
    return stackItem;
}

/*
 * Pop an audit event from the stack by deleting the memory context that
 * contains it.  The callback to stack_free() does the actual pop.
 */
static void
stack_pop(int64 stackId)
{
PGA_FUNCTION_TRACE("IN-");
    /* Make sure what we want to delete is at the top of the stack */
    if (auditEventStack != NULL && auditEventStack->stackId == stackId)
        MemoryContextDelete(auditEventStack->contextAudit);
    else
        ELOG(ERROR, "pgaudit stack item " INT64_FORMAT " not found on top - cannot pop",
             stackId);
PGA_FUNCTION_TRACE("OUT");
}

/*
 * Check that an item is on the stack.  If not, an error will be raised since
 * this is a bad state to be in and it might mean audit records are being lost.
 */
static void
stack_valid(int64 stackId)
{
    AuditEventStackItem *nextItem = auditEventStack;

    /* Look through the stack for the stack entry */
    while (nextItem != NULL && nextItem->stackId != stackId)
        nextItem = nextItem->next;

    /* If we didn't find it, something went wrong. */
    if (nextItem == NULL)
        ELOG(ERROR, "pgaudit stack item " INT64_FORMAT
             " not found - top of stack is " INT64_FORMAT "",
             stackId,
             auditEventStack == NULL ? (int64) -1 : auditEventStack->stackId);
}

/*
 * Appends a properly quoted CSV field to StringInfo.
 */
static void
append_valid_csv(StringInfoData *buffer, const char *appendStr)
{
    const char *pChar;

    /*
     * If the append string is null then do nothing.  NULL fields are not
     * quoted in CSV.
     */
    if (appendStr == NULL)
        return;

    /* Only format for CSV if appendStr contains: ", comma, \n, \r */
    if (strstr(appendStr, ",") || strstr(appendStr, "\"") ||
        strstr(appendStr, "\n") || strstr(appendStr, "\r"))
    {
        appendStringInfoCharMacro(buffer, '"');

        for (pChar = appendStr; *pChar; pChar++)
        {
            if (*pChar == '"')    /* double single quotes */
                appendStringInfoCharMacro(buffer, *pChar);

            appendStringInfoCharMacro(buffer, *pChar);
        }

        appendStringInfoCharMacro(buffer, '"');
    }
    /* Else just append */
    else
        appendStringInfoString(buffer, appendStr);
}

/*
 * Takes an AuditEvent, classifies it, then logs it if appropriate.
 *
 * Logging is decided based on if the statement is in one of the classes being
 * logged or if an object used has been marked for auditing.
 *
 * Objects are marked for auditing by the auditor role being granted access
 * to the object.  The kind of access (INSERT, UPDATE, etc) is also considered
 * and logging is only performed when the kind of access matches the granted
 * right on the object.
 *
 * This will need to be updated if new kinds of GRANTs are added.
 *
 * log_audit_event()
 *   -> pgaudit_classifyStatement()
 *   -> pgaudit_setStatemetIds()
 *   -> pgaudit_getStatementDetail()
 */
static void
pgaudit_classifyStatement(	AuditEventStackItem *stackItem, 
            				int *class,
            				const char **className )
{
	PGA_FUNCTION_TRACE("IN-");

    /* If this event has already been logged don't log it again */
    if (stackItem->auditEvent.logged)
        return;

    /* Classify the statement using log stmt level and the command tag */
    switch (stackItem->auditEvent.logStmtLevel)
    {
            /* All mods go in WRITE class, except EXECUTE */
        case LOGSTMT_MOD:
            *className = CLASS_WRITE;
            *class = LOG_WRITE;

            switch (stackItem->auditEvent.commandTag)
            {
                    /* Currently, only EXECUTE is different */
                case T_ExecuteStmt:
                    *className = CLASS_MISC;
                    *class = LOG_MISC;
                    break;
                default:
                    break;
            }
            break;

            /* These are DDL, unless they are ROLE */
        case LOGSTMT_DDL:
            *className = CLASS_DDL;
            *class = LOG_DDL;

            /* Identify role statements */
            switch (stackItem->auditEvent.commandTag)
            {
                /* In the case of create and alter role redact all text in the
                 * command after the password token for security.  This doesn't
                 * cover all possible cases where passwords can be leaked but
                 * should take care of the most common usage.
                 */
                case T_CreateRoleStmt:
                case T_AlterRoleStmt:

                    if (stackItem->auditEvent.commandText != NULL)
                    {
                        char *commandStr;
                        char *passwordToken;
                        int i;
                        int passwordPos;

                        /* Copy the command string and convert to lower case */
                        commandStr = pstrdup(stackItem->auditEvent.commandText);

                        for (i = 0; commandStr[i]; i++)
                            commandStr[i] =
                                (char)pg_tolower((unsigned char)commandStr[i]);

                        /* Find index of password token */
                        passwordToken = strstr(commandStr, TOKEN_PASSWORD);

                        if (passwordToken != NULL)
                        {
                            /* Copy command string up to password token */
                            passwordPos = (passwordToken - commandStr) +
                                          strlen(TOKEN_PASSWORD);

                            commandStr = palloc(passwordPos + 1 +
                                                strlen(TOKEN_REDACTED) + 1);

                            strncpy(commandStr,
                                    stackItem->auditEvent.commandText,
                                    passwordPos);

                            /* And append redacted token */
                            commandStr[passwordPos] = ' ';

                            strcpy(commandStr + passwordPos + 1, TOKEN_REDACTED);

                            /* Assign new command string */
                            stackItem->auditEvent.commandText = commandStr;
                        }
                    }

                /* Classify role statements */
                case T_GrantStmt:
                case T_GrantRoleStmt:
                case T_DropRoleStmt:
                case T_AlterRoleSetStmt:
                case T_AlterDefaultPrivilegesStmt:
                    *className = CLASS_ROLE;
                    *class = LOG_ROLE;
                    break;

                    /*
                     * Rename and Drop are general and therefore we have to do
                     * an additional check against the command string to see
                     * if they are role or regular DDL.
                     */
                case T_RenameStmt:
                case T_DropStmt:
                    if (pg_strcasecmp(stackItem->auditEvent.command,
                                      COMMAND_ALTER_ROLE) == 0 ||
                        pg_strcasecmp(stackItem->auditEvent.command,
                                      COMMAND_DROP_ROLE) == 0)
                    {
                        *className = CLASS_ROLE;
                        *class = LOG_ROLE;
                    }
                    break;

                default:
                    break;
            }
            break;

            /* Classify the rest */
        case LOGSTMT_ALL:
            switch (stackItem->auditEvent.commandTag)
            {
                    /* READ statements */
                case T_CopyStmt:
                case T_SelectStmt:
                case T_PrepareStmt:
                case T_PlannedStmt:
                    *className = CLASS_READ;
                    *class = LOG_READ;
                    break;

                    /* FUNCTION statements */
                case T_DoStmt:
                    *className = CLASS_FUNCTION;
                    *class = LOG_FUNCTION;
                    break;

                default:
                    break;
            }
            break;

        case LOGSTMT_NONE:
            break;
    }
PGA_FUNCTION_TRACE("OUT");
}

static void
pgaudit_setStatemetIds(AuditEventStackItem *stackItem)
{
PGA_FUNCTION_TRACE("IN-");
    /* Set statement and substatement IDs */
    if (stackItem->auditEvent.statementId == 0)
    {
        /* If nothing has been logged yet then create a new statement Id */
        if (!statementLogged)
        {
            statementTotal++;
            statementLogged = true;
        }

        stackItem->auditEvent.statementId = statementTotal;
        stackItem->auditEvent.substatementId = ++substatementTotal;
    }
PGA_FUNCTION_TRACE("OUT");
}

static void
pgaudit_getStatementDetail(AuditEventStackItem *stackItem, StringInfoData auditStr)
{
PGA_FUNCTION_TRACE("IN-");
    /*
     * If auditLogStatmentOnce is true, then only log the statement and
     * parameters if they have not already been logged for this substatement.
     */
    if (!stackItem->auditEvent.statementLogged || !auditLogStatementOnce)
    {
        append_valid_csv(&auditStr, stackItem->auditEvent.commandText);
        appendStringInfoCharMacro(&auditStr, ',');

        /* Handle parameter logging, if enabled. */
        if (auditLogParameter)
        {
            int paramIdx;
            int numParams;
            StringInfoData paramStrResult;

            ParamListInfo paramList = stackItem->auditEvent.paramList;

            numParams = paramList == NULL ? 0 : paramList->numParams;

            /* Create the param substring */
            initStringInfo(&paramStrResult);

            /* Iterate through all params */
            for (paramIdx = 0; paramList != NULL && paramIdx < numParams;
                 paramIdx++)
            {
                ParamExternData *prm = &paramList->params[paramIdx];
                Oid typeOutput;
                bool typeIsVarLena;
                char *paramStr;

                /* Add a comma for each param */
                if (paramIdx != 0)
                    appendStringInfoCharMacro(&paramStrResult, ' ');

                /* Skip if null or if oid is invalid */
                if (prm->isnull || !OidIsValid(prm->ptype))
                    continue;

                /* Output the string */
                getTypeOutputInfo(prm->ptype, &typeOutput, &typeIsVarLena);
                paramStr = OidOutputFunctionCall(typeOutput, prm->value);

                append_valid_csv(&paramStrResult, paramStr);
                pfree(paramStr);
            }

            if (numParams == 0)
            {
                appendStringInfoString(&auditStr, "<none>");
            	pgaudit_setTextToField(command_parameter_i, NULL, true);
            }
            else
        	{
        		append_valid_csv(&auditStr, paramStrResult.data);
            	pgaudit_setTextToField(	command_parameter_i, 
            							paramStrResult.data, 
            							true);
        	}
        }
        else
    	{
    		appendStringInfoString(&auditStr, "<not logged>");
            pgaudit_setTextToField(command_parameter_i, NULL, true);
    	}
    
    	stackItem->auditEvent.statementLogged = true;
    
    }
    else
        /* we were asked to not log it */
        appendStringInfoString(&auditStr,
                               "<previously logged>,<previously logged>");
PGA_FUNCTION_TRACE("OUT");
}

static void
log_audit_event(AuditEventStackItem *stackItem)
{
    /* By default, put everything in the MISC class. */
    int class = LOG_MISC;
    const char *className = CLASS_MISC;
    MemoryContext contextOld;
    StringInfoData auditStr;
    
PGA_FUNCTION_TRACE("IN-");
    pgaudit_classifyStatement(stackItem, &class, &className );

    /*
     * This code was ommited for collect data for SESSON-AUDIT-LOGGING.
     * ----------
     * Only log the statement if:
     *
     * 1. If object was selected for audit logging (granted), or
     * 2. The statement belongs to a class that is being logged
     *
     * If neither of these is true, return. --> Continue !
     *----------
     *    if (!stackItem->auditEvent.granted && !(auditLogBitmap & class))
     *        return;
     *----------
     */


    /* Set statement and substatement IDs */
    pgaudit_setStatemetIds(stackItem);

    /*
     * Use audit memory context in case something is not free'd while
     * appending strings and parameters.
     */
    contextOld = MemoryContextSwitchTo(stackItem->contextAudit);

    /*
     * Create the audit substring
     *
     * The type-of-audit-log and statement/substatement ID are handled below,
     * this string is everything else.
     */
    initStringInfo(&auditStr);
    append_valid_csv(&auditStr, stackItem->auditEvent.command);

    appendStringInfoCharMacro(&auditStr, ',');
    append_valid_csv(&auditStr, stackItem->auditEvent.objectType);

    appendStringInfoCharMacro(&auditStr, ',');
    append_valid_csv(&auditStr, stackItem->auditEvent.objectName);

#ifdef BUG310_20160126 /* Trial,Delete: BUG#310 */
    /* Collect Classes by the Name */
    if( !keptDMLLogData )
    {
        pgaudit_setTextToField(	class_i, (char *)className, true);
        pgaudit_setTextToField(	command_tag_i, 
            					(char *)stackItem->auditEvent.command, 
            					true);
    }
    
    pgaudit_setTextToField(	object_type_i, 
            				(char *)(stackItem->auditEvent.objectType), 
            				true);
    pgaudit_setTextToField(	object_id_i, 
            				stackItem->auditEvent.objectName, 
            				true);
    pgaudit_setTextToField(	current_user_i, 
            				GetUserNameFromId(GetUserId(),false),
            				true);
    pgaudit_setTimestamps();
#endif
    
    /*
     * If auditLogStatmentOnce is true, then only log the statement and
     * parameters if they have not already been logged for this substatement.
     */
    appendStringInfoCharMacro(&auditStr, ',');
    pgaudit_getStatementDetail(stackItem, auditStr);

    /*
     * Log the audit entry.  Note: use of INT64_FORMAT here is bad for
     * translatability, but we currently haven't got translation support in
     * pgaudit anyway.
     */
    if ( stackItem->auditEvent.granted )
    {
        /* use satack context (stackItem->contextAuditi) */
        StringInfoData objectLogMessage;

        initStringInfo(&objectLogMessage);
        appendStringInfo(&objectLogMessage, 
            "AUDIT: %s," INT64_FORMAT "," INT64_FORMAT ",%s,%s",
            AUDIT_TYPE_OBJECT,
            stackItem->auditEvent.statementId,
            stackItem->auditEvent.substatementId,
            className,
            auditStr.data);

        /* 
         * output to the logger, serverlog or syslog 
         */
        pgaudit_doOutput(objectLogMessage.data);
    }
    else
    {
#ifndef BUG310_20160126 /* Trial,Insert : BUG#310 & 316 */
        /* Collect Classes by the Name */
        if( !keptDMLLogData )
        {
            pgaudit_setTextToField(	class_i, (char *)className, true);
            pgaudit_setTextToField(	command_tag_i, 
            						(char *)stackItem->auditEvent.command, 
            						true);
            pgaudit_setTextToField(	object_type_i, 
            						(char *)(stackItem->auditEvent.objectType), 
            						true);
            pgaudit_setTextToField(	object_id_i, 
            						stackItem->auditEvent.objectName, 
            						true);
        }
    
        pgaudit_setTextToField(	command_text_i, 
            					(char *)stackItem->auditEvent.commandText, 
            					true);
        pgaudit_setTextToField(	current_user_i, 
            					GetUserNameFromId(GetUserId(),false),
            					true);
        pgaudit_setTimestamps();
#endif
        set_statement_id();
        set_substatement_id();
        set_command_result(0);
        
        pgaudit_executeRules();
        pgaudit_printData4debug();
    }

    stackItem->auditEvent.logged = true;

    MemoryContextSwitchTo(contextOld);
    
PGA_FUNCTION_TRACE("OUT");
}

/*
 * Classify Object
 */
static void
pgaudit_classifyObject(AuditEventStackItem *stackItem)
{
    /* By default, put everything in the MISC class. */
    int class = LOG_MISC;
    const char *className = CLASS_MISC;
    MemoryContext contextOld;
    StringInfoData auditStr;

PGA_FUNCTION_TRACE("IN-");
    pgaudit_classifyStatement(stackItem, &class, &className );

    /* Set statement and substatement IDs */
    pgaudit_setStatemetIds(stackItem);

    /* cllect data for SESSION-AUDIT-LOGGING.  */
    pgaudit_setTextToField(	object_type_i, 
            			   	(char*)stackItem->auditEvent.objectType, 
            				false);
    pgaudit_setTextToField(	object_id_i, 
            				(char*)stackItem->auditEvent.objectName, 
            				false);
    pgaudit_setTextToField(	command_tag_i, 
            				(char*)stackItem->auditEvent.command, 
            				false);
    pgaudit_setTextToField(	class_i, (char*)className, false);
    pgaudit_setTextToField(	current_user_i, 
            				GetUserNameFromId(GetUserId(),false),
            				true);
    keptDMLLogData = true;

    /*
     * Use audit memory context in case something is not free'd while
     * appending strings and parameters.
     */
    contextOld = MemoryContextSwitchTo(stackItem->contextAudit);
    
    /*
     * If auditLogStatmentOnce is true, then only log the statement and
     * parameters if they have not already been logged for this substatement.
     */
    initStringInfo(&auditStr);
    pgaudit_getStatementDetail(stackItem, auditStr);

    stackItem->auditEvent.logged = true;

    MemoryContextSwitchTo(contextOld);
PGA_FUNCTION_TRACE("OUT");
}

/*
 * Check if the role or any inherited role has any permission in the mask.  The
 * public role is excluded from this check and superuser permissions are not
 * considered.
 */
static bool
audit_on_acl(Datum aclDatum,
             Oid auditOid,
             AclMode mask)
{
    bool result = false;
    Acl *acl;
    AclItem *aclItemData;
    int aclIndex;
    int aclTotal;

PGA_FUNCTION_TRACE("IN-");
    /* Detoast column's ACL if necessary */
    acl = DatumGetAclP(aclDatum);

    /* Get the acl list and total number of items */
    aclTotal = ACL_NUM(acl);
    aclItemData = ACL_DAT(acl);

    /* Check privileges granted directly to auditOid */
    for (aclIndex = 0; aclIndex < aclTotal; aclIndex++)
    {
        AclItem *aclItem = &aclItemData[aclIndex];

        if (aclItem->ai_grantee == auditOid &&
            aclItem->ai_privs & mask)
        {
            result = true;
            break;
        }
    }

    /*
     * Check privileges granted indirectly via role memberships. We do this in
     * a separate pass to minimize expensive indirect membership tests.  In
     * particular, it's worth testing whether a given ACL entry grants any
     * privileges still of interest before we perform the has_privs_of_role
     * test.
     */
    if (!result)
    {
        for (aclIndex = 0; aclIndex < aclTotal; aclIndex++)
        {
            AclItem *aclItem = &aclItemData[aclIndex];

            /* Don't test public or auditOid (it has been tested already) */
            if (aclItem->ai_grantee == ACL_ID_PUBLIC ||
                aclItem->ai_grantee == auditOid)
                continue;

            /*
             * Check that the role has the required privileges and that it is
             * inherited by auditOid.
             */
            if (aclItem->ai_privs & mask &&
                has_privs_of_role(auditOid, aclItem->ai_grantee))
            {
                result = true;
                break;
            }
        }
    }

    /* if we have a detoasted copy, free it */
    if (acl && (Pointer) acl != DatumGetPointer(aclDatum))
        pfree(acl);

    return result;
PGA_FUNCTION_TRACE("OUT");
}

/*
 * Check if a role has any of the permissions in the mask on a relation.
 */
static bool
audit_on_relation(Oid relOid,
                  Oid auditOid,
                  AclMode mask)
{
    bool result = false;
    HeapTuple tuple;
    Datum aclDatum;
    bool isNull;

PGA_FUNCTION_TRACE("IN-");
    /* Get relation tuple from pg_class */
    tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));
    if (!HeapTupleIsValid(tuple))
        return false;

    /* Get the relation's ACL */
    aclDatum = SysCacheGetAttr(RELOID, tuple, Anum_pg_class_relacl,
                               &isNull);

    /* Only check if non-NULL, since NULL means no permissions */
    if (!isNull)
        result = audit_on_acl(aclDatum, auditOid, mask);

    /* Free the relation tuple */
    ReleaseSysCache(tuple);

PGA_FUNCTION_TRACE("OUT");
    return result;
}

/*
 * Check if a role has any of the permissions in the mask on a column.
 */
static bool
audit_on_attribute(Oid relOid,
                   AttrNumber attNum,
                   Oid auditOid,
                   AclMode mask)
{
    bool result = false;
    HeapTuple attTuple;
    Datum aclDatum;
    bool isNull;

PGA_FUNCTION_TRACE("IN-");
    /* Get the attribute's ACL */
    attTuple = SearchSysCache2(ATTNUM,
                               ObjectIdGetDatum(relOid),
                               Int16GetDatum(attNum));
    if (!HeapTupleIsValid(attTuple))
        return false;

    /* Only consider attributes that have not been dropped */
    if (!((Form_pg_attribute) GETSTRUCT(attTuple))->attisdropped)
    {
        aclDatum = SysCacheGetAttr(ATTNUM, attTuple, Anum_pg_attribute_attacl,
                                   &isNull);

        if (!isNull)
            result = audit_on_acl(aclDatum, auditOid, mask);
    }

    /* Free attribute */
    ReleaseSysCache(attTuple);

PGA_FUNCTION_TRACE("OUT");
    return result;
}

/*
 * Check if a role has any of the permissions in the mask on a column in
 * the provided set.  If the set is empty, then all valid columns in the
 * relation will be tested.
 */
static bool
audit_on_any_attribute(Oid relOid,
                       Oid auditOid,
                       Bitmapset *attributeSet,
                       AclMode mode)
{
    bool result = false;
    AttrNumber col;
    Bitmapset *tmpSet;

PGA_FUNCTION_TRACE("IN-");
    /* If bms is empty then check for any column match */
    if (bms_is_empty(attributeSet))
    {
        HeapTuple classTuple;
        AttrNumber nattrs;
        AttrNumber curr_att;

        /* Get relation to determine total columns */
        classTuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));

        if (!HeapTupleIsValid(classTuple))
            return false;

        nattrs = ((Form_pg_class) GETSTRUCT(classTuple))->relnatts;
        ReleaseSysCache(classTuple);

        /* Check each column */
        for (curr_att = 1; curr_att <= nattrs; curr_att++)
            if (audit_on_attribute(relOid, curr_att, auditOid, mode))
                return true;
    }

    /* bms_first_member is destructive, so make a copy before using it. */
    tmpSet = bms_copy(attributeSet);

    /* Check each column */
    while ((col = bms_first_member(tmpSet)) >= 0)
    {
        col += FirstLowInvalidHeapAttributeNumber;

        if (col != InvalidAttrNumber &&
            audit_on_attribute(relOid, col, auditOid, mode))
        {
            result = true;
            break;
        }
    }

    bms_free(tmpSet);

PGA_FUNCTION_TRACE("OUT");
    return result;
}

/*
 * Create AuditEvents for SELECT/DML operations via executor permissions checks.
 */
static void
log_select_dml(Oid auditOid, List *rangeTabls)
{
    ListCell *lr;
    bool first = true;
    bool found = false;

PGA_FUNCTION_TRACE("IN-");
    /* Do not log if this is an internal statement */
    if (internalStatement)
        return;

    foreach(lr, rangeTabls)
    {
        Oid relOid;
        Relation rel;
        RangeTblEntry *rte = lfirst(lr);

        /* We only care about tables, and can ignore subqueries etc. */
        if (rte->rtekind != RTE_RELATION)
            continue;

        found = true;

        /*
         * Don't log if the session user is not a member of the current
         * role.  This prevents contents of security definer functions
         * from being logged and supresses foreign key queries unless the
         * session user is the owner of the referenced table.
         */
        if (!is_member_of_role(GetSessionUserId(), GetUserId()))
            return;

        /*
         * If we are not logging all-catalog queries (auditLogCatalog is
         * false) then filter out any system relations here.
         */
        relOid = rte->relid;
        rel = relation_open(relOid, NoLock);

        if (!auditLogCatalog && IsSystemNamespace(RelationGetNamespace(rel)))
        {
            relation_close(rel, NoLock);
            continue;
        }

        /*
         * Default is that this was not through a grant, to support session
         * logging.  Will be updated below if a grant is found.
         */
        auditEventStack->auditEvent.granted = false;

        /*
         * If this is the first RTE then session log unless auditLogRelation
         * is set.
         */
    
     	if (first && utilityStatement && !executorStart)
            log_audit_event(auditEventStack);
    
        /*
         * We don't have access to the parsetree here, so we have to generate
         * the node type, object type, and command tag by decoding
         * rte->requiredPerms and rte->relkind.
         */
        if (rte->requiredPerms & ACL_INSERT)
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_MOD;
            auditEventStack->auditEvent.commandTag = T_InsertStmt;
            auditEventStack->auditEvent.command = COMMAND_INSERT;
        }
        else if (rte->requiredPerms & ACL_UPDATE)
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_MOD;
            auditEventStack->auditEvent.commandTag = T_UpdateStmt;
            auditEventStack->auditEvent.command = COMMAND_UPDATE;
        }
        else if (rte->requiredPerms & ACL_DELETE)
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_MOD;
            auditEventStack->auditEvent.commandTag = T_DeleteStmt;
            auditEventStack->auditEvent.command = COMMAND_DELETE;
        }
        else if (rte->requiredPerms & ACL_SELECT)
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_ALL;
            auditEventStack->auditEvent.commandTag = T_SelectStmt;
            auditEventStack->auditEvent.command = COMMAND_SELECT;
        }
        else
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_ALL;
            auditEventStack->auditEvent.commandTag = T_Invalid;
            auditEventStack->auditEvent.command = COMMAND_UNKNOWN;
        }

        /* Use the relation type to assign object type */
        switch (rte->relkind)
        {
            case RELKIND_RELATION:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_TABLE;
                break;

            case RELKIND_INDEX:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_INDEX;
                break;

            case RELKIND_SEQUENCE:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_SEQUENCE;
                break;

            case RELKIND_TOASTVALUE:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_TOASTVALUE;
                break;

            case RELKIND_VIEW:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_VIEW;
                break;

            case RELKIND_COMPOSITE_TYPE:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_COMPOSITE_TYPE;
                break;

            case RELKIND_FOREIGN_TABLE:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_FOREIGN_TABLE;
                break;

            case RELKIND_MATVIEW:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_MATVIEW;
                break;

            default:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_UNKNOWN;
                break;
        }

        /* Get a copy of the relation name and assign it to object name */
        auditEventStack->auditEvent.objectName =
            quote_qualified_identifier(get_namespace_name(
                                           RelationGetNamespace(rel)),
                                       RelationGetRelationName(rel));
        relation_close(rel, NoLock);
 

    	/* 20151218 ...... anyway, collect event items again */
     	if (first && utilityStatement && !executorStart)
        {
            log_audit_event(auditEventStack);
            first = false;
        }

        /* Perform object auditing only if the audit role is valid */
        if (auditOid != InvalidOid)
        {
            AclMode auditPerms =
                (ACL_SELECT | ACL_UPDATE | ACL_INSERT | ACL_DELETE) &
                rte->requiredPerms;

            /*
             * If any of the required permissions for the relation are granted
             * to the audit role then audit the relation
             */
            if (audit_on_relation(relOid, auditOid, auditPerms))
                auditEventStack->auditEvent.granted = true;

            /*
             * Else check if the audit role has column-level permissions for
             * select, insert, or update.
             */
            else if (auditPerms != 0)
            {
                /*
                 * Check the select columns
                 */
                if (auditPerms & ACL_SELECT)
                    auditEventStack->auditEvent.granted =
                        audit_on_any_attribute(relOid, auditOid,
                                               rte->selectedCols,
                                               ACL_SELECT);

                /*
                 * Check the insert columns
                 */
                if (!auditEventStack->auditEvent.granted &&
                    auditPerms & ACL_INSERT)
                    auditEventStack->auditEvent.granted =
                        audit_on_any_attribute(relOid, auditOid,
                                               rte->insertedCols,
                                               auditPerms);

                /*
                 * Check the update columns
                 */
                if (!auditEventStack->auditEvent.granted &&
                    auditPerms & ACL_UPDATE)
                    auditEventStack->auditEvent.granted =
                        audit_on_any_attribute(relOid, auditOid,
                                               rte->updatedCols,
                                               auditPerms);
            }
        }

        /* Do relation level logging if a grant was found */
        if (auditEventStack->auditEvent.granted)
        {
            auditEventStack->auditEvent.logged = false;
            log_audit_event(auditEventStack);
        }
    
    	pgaudit_classifyObject(auditEventStack);

        pfree(auditEventStack->auditEvent.objectName);
    }

    /*
     * If no tables were found that means that RangeTbls was empty or all
     * relations were in the system schema.  In that case still log a session
     * record. Function call is one of that case also.
     */
    if (!found)
    {
        auditEventStack->auditEvent.granted = false;
        auditEventStack->auditEvent.logged = false;

        log_audit_event(auditEventStack);
    }
PGA_FUNCTION_TRACE("OUT");
}

/*
 * Create AuditEvents for non-catalog function execution, as detected by
 * log_object_access() below.
 */
static void
log_function_execute(Oid objectId)
{
    HeapTuple proctup;
    Form_pg_proc proc;
    AuditEventStackItem *stackItem;

PGA_FUNCTION_TRACE("IN-");
    /* Get info about the function. */
    proctup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));

    if (!proctup)
        ELOG(ERROR, "cache lookup failed for function %u", objectId);

    proc = (Form_pg_proc) GETSTRUCT(proctup);

    /*
     * Logging execution of all pg_catalog functions would make the log
     * unusably noisy.
     */
    if (IsSystemNamespace(proc->pronamespace))
    {
        ReleaseSysCache(proctup);
        return;
    }

    /* Push audit event onto the stack */
    stackItem = stack_push();

    /* Generate the fully-qualified function name. */
    stackItem->auditEvent.objectName =
        quote_qualified_identifier(get_namespace_name(proc->pronamespace),
                                   NameStr(proc->proname));
    ReleaseSysCache(proctup);

    /* Log the function call */
    stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
    stackItem->auditEvent.commandTag = T_DoStmt;
    stackItem->auditEvent.command = COMMAND_EXECUTE;
    stackItem->auditEvent.objectType = OBJECT_TYPE_FUNCTION;
    stackItem->auditEvent.commandText = stackItem->next->auditEvent.commandText;

    log_audit_event(stackItem);

    /* Pop audit event from the stack */
    stack_pop(stackItem->stackId);
PGA_FUNCTION_TRACE("OUT");
}

/*-----------------------------------------------------------------------------
 * Hook functions
 */
static ExecutorCheckPerms_hook_type next_ExecutorCheckPerms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;
static ExecutorStart_hook_type next_ExecutorStart_hook = NULL;
static emit_log_hook_type next_emit_log_hook = NULL;
static ExecutorEnd_hook_type next_ExecutorEnd_hook = NULL;
static ClientAuthentication_hook_type next_ClientAuthentication_hook = NULL;

/*
 * Hook ExecutorStart to get the query text and basic command type for queries
 * that do not contain a table and so can't be idenitified accurately in
 * ExecutorCheckPerms.
 */
static void
pgaudit_ExecutorStart_hook(QueryDesc *queryDesc, int eflags)
{
    AuditEventStackItem *stackItem = NULL;
    executorStart = true;

PGA_FUNCTION_TRACE("IN-");
    /* Clear the item logging fields */
    pgaudit_initItems(false);

    /* Set application_name, command_text, and virtual_x_id */
    pgaudit_setTextToField(	application_name_i, application_name, true);
    pgaudit_setTextToField(	command_text_i, 
            				(char *)(queryDesc->sourceText), 
            				true);
    set_virtual_x_id();
    
    if (!internalStatement)
    {
        /* Push the audit even onto the stack */
        stackItem = stack_push();

        /* Initialize command using queryDesc->operation */
        switch (queryDesc->operation)
        {
            case CMD_SELECT:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
                stackItem->auditEvent.commandTag = T_SelectStmt;
                stackItem->auditEvent.command = COMMAND_SELECT;
                break;

            case CMD_INSERT:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_MOD;
                stackItem->auditEvent.commandTag = T_InsertStmt;
                stackItem->auditEvent.command = COMMAND_INSERT;
                break;

            case CMD_UPDATE:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_MOD;
                stackItem->auditEvent.commandTag = T_UpdateStmt;
                stackItem->auditEvent.command = COMMAND_UPDATE;
                break;

            case CMD_DELETE:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_MOD;
                stackItem->auditEvent.commandTag = T_DeleteStmt;
                stackItem->auditEvent.command = COMMAND_DELETE;
                break;

            default:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
                stackItem->auditEvent.commandTag = T_Invalid;
                stackItem->auditEvent.command = COMMAND_UNKNOWN;
                break;
        }

        /* Initialize the audit event */
        stackItem->auditEvent.commandText = queryDesc->sourceText;
        stackItem->auditEvent.paramList = queryDesc->params;
    }

    /* Call the previous hook or standard function */
    if (next_ExecutorStart_hook)
        next_ExecutorStart_hook(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);

    /*
     * Move the stack memory context to the query memory context.  This needs
     * to be done here because the query context does not exist before the
     * call to standard_ExecutorStart() but the stack item is required by
     * pgaudit_ExecutorCheckPerms_hook() which is called during
     * standard_ExecutorStart().
     */
    if (stackItem)
        MemoryContextSetParent(stackItem->contextAudit,
                               queryDesc->estate->es_query_cxt);
    
PGA_FUNCTION_TRACE("OUT");
}

/*
 * Hook ExecutorCheckPerms to do session and object auditing for DML.
 */
static bool
pgaudit_ExecutorCheckPerms_hook(List *rangeTabls, bool Aabort)
{
    Oid auditOid;

PGA_FUNCTION_TRACE("IN-");
    /* Get the audit oid if the role exists */
    auditOid = get_role_oid(auditRole, true);

    /*
     * This code was ommited for collect data for SESSON-AUDIT-LOGGING.
     * Log DML if the audit role is valid or session logging is enabled
     *   if ((auditOid != InvalidOid || auditLogBitmap != 0) &&
     */

    if (!IsAbortedTransactionBlockState())
        log_select_dml(auditOid, rangeTabls);

    /* Call the next hook function */
    if (next_ExecutorCheckPerms_hook &&
        !(*next_ExecutorCheckPerms_hook) (rangeTabls, Aabort))
        return false;

PGA_FUNCTION_TRACE("OUT");
    return true;
}

/*
 * Hook ProcessUtility to do session auditing for DDL and utility commands.
 */
static void
pgaudit_ProcessUtility_hook(Node *parsetree,
                             const char *queryString,
                             ProcessUtilityContext context,
                             ParamListInfo params,
                             DestReceiver *dest,
                             char *completionTag)
{
    AuditEventStackItem *stackItem = NULL;
    int64 stackId = 0;
    
PGA_FUNCTION_TRACE("IN-");
    /* Clear the item logging fields */
    pgaudit_initItems(false);

    /*
     * Don't audit substatements.  All the substatements we care about should
     * be covered by the event triggers.
     */
    if (context <= PROCESS_UTILITY_QUERY && !IsAbortedTransactionBlockState())
    {
        /* Process top level utility statement */
        if (context == PROCESS_UTILITY_TOPLEVEL)
        {
            if (auditEventStack != NULL)
                ELOG(ERROR, "pgaudit stack is not empty");

            stackItem = stack_push();
            stackItem->auditEvent.paramList = params;
        }
        else
            stackItem = stack_push();

        stackId = stackItem->stackId;
        stackItem->auditEvent.logStmtLevel = GetCommandLogLevel(parsetree);
        stackItem->auditEvent.commandTag = nodeTag(parsetree);
        stackItem->auditEvent.command = CreateCommandTag(parsetree);
        stackItem->auditEvent.commandText = queryString;

        /*
         * If this is a DO block log it before calling the next ProcessUtility
         * hook.
         *
         * auditLogBitmap control was ommitd. 2015.03
         */
          if ( stackItem->auditEvent.commandTag == T_DoStmt 
            && !IsAbortedTransactionBlockState())
          {
            pgaudit_setTextToField(application_name_i, application_name, true);
            pgaudit_setTextToField(command_text_i, (char *)queryString, true);
            set_virtual_x_id();
          
            log_audit_event(stackItem);
          }
    }

    /* Call the standard process utility chain. */
    pgaudit_setTextToField(application_name_i, application_name, true);
    pgaudit_setTextToField(command_text_i, (char *)queryString, true);
    set_virtual_x_id();

   	utilityStatement = true;
    if (next_ProcessUtility_hook)
        (*next_ProcessUtility_hook) (parsetree, queryString, context,
                                     params, dest, completionTag);
    else
        standard_ProcessUtility(parsetree, queryString, context,
                                params, dest, completionTag);
   	utilityStatement = false;

    /*
     * Process the audit event if there is one.  Also check that this event
     * was not popped off the stack by a memory context being free'd
     * elsewhere.
     */
    if (stackItem && !IsAbortedTransactionBlockState())
    {
        /*
         * Make sure the item we want to log is still on the stack - if not
         * then something has gone wrong and an error will be raised.
         */
        stack_valid(stackId);

        /*
         * Log the utility command if logging is on, the command has not
         * already been logged by another hook, and the transaction is not
         * aborted.
         *
         * if (auditLogBitmap != 0 )
         */
    	if (!stackItem->auditEvent.logged)
    	{
            pgaudit_setTextToField(application_name_i, application_name, true);
    		set_virtual_x_id();
            pgaudit_setTextToField( command_text_i, 
            						(char *)stackItem->auditEvent.commandText, 
            						true);
            pgaudit_setTextToField(connection_message_i, NULL, true);
    
            log_audit_event(stackItem);
    	}
    }
    
   	keptDMLLogData = false;
    
PGA_FUNCTION_TRACE("OUT");
}

/*
 * Hook object_access_hook to provide fully-qualified object names for function
 * calls.
 */
static void
pgaudit_object_access_hook(ObjectAccessType access,
                            Oid classId,
                            Oid objectId,
                            int subId,
                            void *arg)
{
PGA_FUNCTION_TRACE("IN-");
    /*
     * This code was ommited for collect data for SESSON-AUDIT-LOGGING.
     * if (auditLogBitmap & LOG_FUNCTION && access == OAT_FUNCTION_EXECUTE &&
     */

    if (access == OAT_FUNCTION_EXECUTE &&
        auditEventStack && !IsAbortedTransactionBlockState())
        log_function_execute(objectId);

    if (next_object_access_hook)
        (*next_object_access_hook) (access, classId, objectId, subId, arg);
PGA_FUNCTION_TRACE("OUT");
}

/*
 * Hook pgaudit_ExecutorEnd_hook to provide DML Logs. 
 */
static void
pgaudit_ExecutorEnd_hook(QueryDesc *queryDesc)
{
PGA_FUNCTION_TRACE("IN-");
    if( keptDMLLogData )
    {
        /* stop the call */
        keptDMLLogData = false;

        pgaudit_setTimestamps();
        set_statement_id();
        set_substatement_id();
        set_command_result(0);

        pgaudit_executeRules();
        pgaudit_printData4debug();
    }
    
    executorStart = false;
    
    /* Call the previous hook or standard function */
    if (next_ExecutorEnd_hook)
        (*next_ExecutorEnd_hook) (queryDesc);
    else
        standard_ExecutorEnd(queryDesc);
PGA_FUNCTION_TRACE("OUT");
isStartTrace=true;
}

/* 2016.03
 * pgaudit_emit_log_hook()
 *   -> pgaudit_emit_log_hook_body()
 *     -> pgaudit_extractRemort()
 *
 * CONNECTION class Logging
 *   Log startup of database system, connection, buckup, and errors.
 */

static void 
pgaudit_extractRemort(char *message)
{
    char *remoteHost=pgauditDataIndexes[remote_host_i].data.fix;
    char *remotePort=pgauditDataIndexes[remote_port_i].data.fix;
    int i=0, j=0;
    /*
     * This codes depend on the format of the message.
     *
     * This exrract remote host & port names by the letter '=' and ' '
     * 		<"host" in any locale>'='<hostmene>' '
     * 		<"port" in any locale>'='<portmene>' '
     * And, any other character is not acceptable between the '=' and 
     * the names.
     * The blanck after name may be a NULL('\0').
     *
     * (The code to extract might be a function separated.)
     */

    /* extract remote Host */
    j = 0;
    while( (message[i] != '=') && (message[i] != '\0') )
        i++;
    if( message[i] == '=' )
    {
        i++;
        remoteHost[j++] = ' ';
        while( (message[i] != ' ') && (message[i] != '\0') && (j <= 256) )
            remoteHost[j++] = message[i++];
        remoteHost[j++] = ' ';
        remoteHost[j++] = '\0';
    }
    else
        strcpy(remoteHost, pgauditNullString);

    /* extract remote Port */
    j = 0;
    while( (message[i] != '=') && (message[i] != '\0') )
        i++;
    if( message[i] == '=' )
    {
        i++;
        remotePort[j++] = ' ';
        while( (message[i] != ' ') && (message[i] != '\0')  && (j <= 6) )
            remotePort[j++] = message[i++];
        remotePort[j++] = ' ';
        remotePort[j++] = '\0';
    }
    else
        strcpy(remotePort, pgauditNullString);
}
static void
pgaudit_emit_log_hook_body(ErrorData *edata)
{
    bool isConnect = false;
    /*
     *	CONNECTION class Logging
     *
     *  read an event from the message, and then outputs a SESSION-AUDIT-LOG.
     */

    ELOG(DEBUG3, "%s:edata->messag=[%s]", __func__, edata->message);
    /* connection received */
    if( strstr(edata->message, Msg_Connection1))
    {
        pgaudit_initItems(true);
        pgaudit_setTextToField(class_i, COMMAND_CONNECT, true);
        pgaudit_setTextToField(connection_message_i, MESSAGE_RECEIVED, true);
        pgaudit_extractRemort(edata->message);

        /* recover output_to_server to original GUC value */
     	edata->output_to_server = saveLogConnections;
    }

    /* connection authorized */
    else if( strstr(edata->message, Msg_Connection2) )
    {
        pgaudit_initItems(true);
        pgaudit_setTextToField(class_i, COMMAND_CONNECT, true);
        pgaudit_setTextToField(connection_message_i, MESSAGE_AUTHORIZED, true);
        isConnect = true;
        
        /* recover output_to_server to original GUC value */
        edata->output_to_server = saveLogConnections;
    }

    /* disconnection */
    else if( 	strstr(edata->message, Msg_DisConnect) )
    {
        pgaudit_initItems(true);
        pgaudit_setTextToField(class_i, COMMAND_CONNECT, true);
        pgaudit_setTextToField(connection_message_i, MESSAGE_DISCONNECTED, true);
        pgaudit_setTextToField(current_user_i, NULL, true);
        
        /* recover output_to_server to original GUC value */
        edata->output_to_server = saveLogDisconnections;
    }

    /* database system was shut down at */
    else if ( 	strstr(edata->message, Msg_ShutDown1) 
        || 	  	strstr(edata->message, Msg_ShutDown2) )
    {
        pgaudit_initItems(true);
        pgaudit_setTextToField(class_i, COMMAND_SYSTEM, true);
        pgaudit_setTextToField(connection_message_i, MESSAGE_NORMALENDED, true);
    }

    /* database system was interrupted ... */
    else if ( 	strstr(edata->message, Msg_Interrupt1) 
        || 		strstr(edata->message, Msg_Interrrupt2) 
        || 		strstr(edata->message, Msg_Interrrupt3) )
    {
        pgaudit_initItems(true);
        pgaudit_setTextToField(class_i, COMMAND_SYSTEM, true);
        pgaudit_setTextToField(connection_message_i, MESSAGE_INTERRUPTED, true);
    }

    /* database system is ready to accept connections */
    else if( 	strstr(edata->message, Msg_Redy))
    {
        pgaudit_initItems(true);
        pgaudit_setTextToField(class_i, COMMAND_SYSTEM, true);
        pgaudit_setTextToField(connection_message_i, MESSAGE_READY, true);
    }

    /* received replication command */
    else if( 	strstr(edata->message, Msg_Replication))
    {
        pgaudit_initItems(true);
        pgaudit_setTextToField(class_i, COMMAND_BACKUP, true);
        pgaudit_setTextToField(application_name_i, application_name, true);
    }
    
    /* selected new timeline */
    else if( 	strstr(edata->message, Msg_NewTimeline))
    {
        pgaudit_initItems(true);
        pgaudit_setTextToField(class_i, COMMAND_SYSTEM, true);
        pgaudit_setTextToField(connection_message_i, edata->message, true); 
    }

    /* paramater Log_connections changed */
    else if ( strstr(edata->message, Msg_PC_LC))
    {
    	saveLogConnections = Log_connections;
    	Log_connections = true;
        return;
    }

    /* paramater Log_disconnections changed */
    else if ( strstr(edata->message, Msg_PC_LD))
    {
    	saveLogDisconnections = Log_disconnections;
    	Log_disconnections = true;
    ELOG(WARNING,"Log_disconnections=[%d],saveLogDisconnections=[%d]",Log_disconnections,saveLogDisconnections);
        return;
    }

    /* paramater log_replication_commands changed */
    else if ( strstr(edata->message, Msg_PC_RP))
    {
    	saveLogReplicationCommands = log_replication_commands;
    	log_replication_commands = true;
    ELOG(WARNING,"Log_disconnections=[%d],saveLogReplicationCommands=[%d]",log_replication_commands,saveLogReplicationCommands);
        return;
    }

    /* SQL Error */ 
    else if( 	strncmp(unpack_sql_state(edata->sqlerrcode),"00",2) )
    {
        ELOG(DEBUG3, "unpack_sql_state(edata->sqlerrcode)=%s",
            unpack_sql_state(edata->sqlerrcode));

        if (keptDMLLogData) 
        {
            /* 
             * In order to avoid the confusion of a complex statement (COPY or
             *  something else), clears the data item of object ID, and type.
             */
            pgaudit_setTextToField(object_id_i, NULL, true);
            pgaudit_setTextToField(object_type_i, NULL, true);

            /* Use current statement id. (already count uped) */
            set_statement_id();
            set_substatement_id();
        }
        else
        {
            /*
             *  No data has kept for current statement. 
             *  May be a pase error or anything else.
             */
            pgaudit_initItems(false);
            set_virtual_x_id();

            /* Count up the statement id. */
            statementTotal++;
            set_statement_id();
            pgaudit_setTextToField(sub_statement_id_i, "1", true);
        }
        set_command_result( edata->sqlerrcode );
        pgaudit_setTextToField(class_i, "ERROR", true);
        pgaudit_setTextToField(command_text_i, (char*)debug_query_string, true);
    }
    
    else
        return;

    pgaudit_setTextToField(application_name_i, application_name, true);
    set_process_id();				/* pid_i */
    set_remote_host();				/* remote_host_i*/
    set_remote_port();				/* remote_port_i*/
    set_database_name();			/* database_i */
    set_session_user_name();		/* user_i */
    set_virtual_x_id();				/* virtual_xid_i */
    pgaudit_setTimestamps();		/* timestamp_i */

    /* output SESSION-AUDIT-LOG */
    pgaudit_executeRules();
    pgaudit_printData4debug();

    /*
 	 * set interim current user name.
 	 * This may appier in the ERROR class adit logs before any SQL is executed.
 	 */
    if (isConnect)
        set_interim_current_user();

   	keptDMLLogData = false;
}

static void
pgaudit_emit_log_hook(ErrorData *edata)
{
    /* Protect from recrcuve call, also from timing before _PG_init(). */
    if( (edata->elevel > DEBUG1) && isPGinitDone && (!emitLogCalled) )
    {
        emitLogCalled++;
PGA_FUNCTION_TRACE("IN-");
        pgaudit_emit_log_hook_body(edata);
PGA_FUNCTION_TRACE("OUT");
        emitLogCalled--;
    }

    if (emitLogCalled)
    {
        edata->output_to_client = false;
        edata->hide_stmt = true;
    }

    /* Call the previous hook or standard function */
    if (next_emit_log_hook)
        (*next_emit_log_hook) (edata);
}


/*
 * pgaudit_ClientAuthentication_hook()
 *
 * Debug codes, to show the timming ClientAuthentication_hook called .
 */
static void
pgaudit_ClientAuthentication_hook(Port * port, int status)
{
PGA_FUNCTION_TRACE("IN-");
    if (next_ClientAuthentication_hook)
        (*next_ClientAuthentication_hook) (port, status);
PGA_FUNCTION_TRACE("OUT");
}

/*--------------------------------------------------------------------------
 * Event trigger functions
 */

/*
 * Supply additional data for (non drop) statements that have event trigger
 * support and can be deparsed.
 *
 * Drop statements are handled below through the older sql_drop event trigger.
 */
Datum
pgaudit_ddl_command_end(PG_FUNCTION_ARGS)
{
    EventTriggerData *eventData;
    int result,
        row;
    TupleDesc spiTupDesc;
    const char *query;
    MemoryContext contextQuery;
    MemoryContext contextOld;
 
PGA_FUNCTION_TRACE("OUT");
    /* 
     * This code was ommited for collect data for SESSON-AUDIT-LOGGING.
     * Continue only if session DDL logging is enabled *
     * if (~auditLogBitmap & LOG_DDL && ~auditLogBitmap & LOG_ROLE)
     *   PG_RETURN_NULL();
     */

    /* Be sure the module was loaded */
    if (!auditEventStack)
        ELOG(ERROR, "pgaudit not loaded before call to "
             "pgaudit_ddl_command_end()");

    /* This is an internal statement - do not log it */
    internalStatement = true;

    /* Make sure the fuction was fired as a trigger */
    if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
        ELOG(ERROR, "not fired by event trigger manager");

    /* Switch memory context for query */
    contextQuery = AllocSetContextCreate(
                            CurrentMemoryContext,
                            "pgaudit_func_ddl_command_end temporary context",
                            ALLOCSET_DEFAULT_MINSIZE,
                            ALLOCSET_DEFAULT_INITSIZE,
                            ALLOCSET_DEFAULT_MAXSIZE);
    contextOld = MemoryContextSwitchTo(contextQuery);

    /* Get information about triggered events */
    eventData = (EventTriggerData *) fcinfo->context;

    auditEventStack->auditEvent.logStmtLevel =
        GetCommandLogLevel(eventData->parsetree);
    auditEventStack->auditEvent.commandTag =
        nodeTag(eventData->parsetree);
    auditEventStack->auditEvent.command =
        CreateCommandTag(eventData->parsetree);

    /* Return objects affected by the (non drop) DDL statement */
    query = "SELECT UPPER(object_type), object_identity, UPPER(command_tag)\n"
            "  FROM pg_catalog.pg_event_trigger_ddl_commands()";

    /* Attempt to connect */
    result = SPI_connect();
    if (result < 0)
        ELOG(ERROR, "pgaudit_ddl_command_end: SPI_connect returned %d",
             result);

    /* Execute the query */
    result = SPI_execute(query, true, 0);
    if (result != SPI_OK_SELECT)
        ELOG(ERROR, "pgaudit_ddl_command_end: SPI_execute returned %d",
             result);

    /* Iterate returned rows */
    spiTupDesc = SPI_tuptable->tupdesc;
    for (row = 0; row < SPI_processed; row++)
    {
        HeapTuple    spiTuple;

        spiTuple = SPI_tuptable->vals[row];

        /* Supply object name and type for audit event */
        auditEventStack->auditEvent.objectType =
            SPI_getvalue(spiTuple, spiTupDesc, 1);
        auditEventStack->auditEvent.objectName =
            SPI_getvalue(spiTuple, spiTupDesc, 2);
        auditEventStack->auditEvent.command =
            SPI_getvalue(spiTuple, spiTupDesc, 3);

        auditEventStack->auditEvent.logged = false;

        /*
         * Identify grant/revoke commands - these are the only non-DDL class
         * commands that should be coming through the event triggers.
         */
        if (pg_strcasecmp(auditEventStack->auditEvent.command, COMMAND_GRANT) == 0 ||
            pg_strcasecmp(auditEventStack->auditEvent.command, COMMAND_REVOKE) == 0)
        {
            NodeTag currentCommandTag = auditEventStack->auditEvent.commandTag;

            auditEventStack->auditEvent.commandTag = T_GrantStmt;
            log_audit_event(auditEventStack);

            auditEventStack->auditEvent.commandTag = currentCommandTag;
        }
        else
            log_audit_event(auditEventStack);
    }

    /* Complete the query */
    SPI_finish();

    MemoryContextSwitchTo(contextOld);
    MemoryContextDelete(contextQuery);

    /* No longer in an internal statement */
    internalStatement = false;

PGA_FUNCTION_TRACE("OUT");
    PG_RETURN_NULL();
}

/*
 * Supply additional data for drop statements that have event trigger support.
 */
Datum
pgaudit_sql_drop(PG_FUNCTION_ARGS)
{
    int result,
        row;
    TupleDesc spiTupDesc;
    const char *query;
    MemoryContext contextQuery;
    MemoryContext contextOld;

PGA_FUNCTION_TRACE("IN-");
    /* 
     * This code was ommited for collect data for SESSON-AUDIT-LOGGING.
     * if (~auditLogBitmap & LOG_DDL)
     *   PG_RETURN_NULL();
     */

    /* Be sure the module was loaded */
    if (!auditEventStack)
        ELOG(ERROR, "pgaudit not loaded before call to "
             "pgaudit_sql_drop()");

    /* This is an internal statement - do not log it */
    internalStatement = true;

    /* Make sure the fuction was fired as a trigger */
    if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
        ELOG(ERROR, "not fired by event trigger manager");

    /* Switch memory context for the query */
    contextQuery = AllocSetContextCreate(
                            CurrentMemoryContext,
                            "pgaudit_func_ddl_command_end temporary context",
                            ALLOCSET_DEFAULT_MINSIZE,
                            ALLOCSET_DEFAULT_INITSIZE,
                            ALLOCSET_DEFAULT_MAXSIZE);
    contextOld = MemoryContextSwitchTo(contextQuery);

    /* Return objects affected by the drop statement */
    query = "SELECT UPPER(object_type),\n"
        "       object_identity\n"
        "  FROM pg_catalog.pg_event_trigger_dropped_objects()\n"
        " WHERE lower(object_type) <> 'type'\n"
        "   AND schema_name <> 'pg_toast'";

    /* Attempt to connect */
    result = SPI_connect();
    if (result < 0)
        ELOG(ERROR, "pgaudit_ddl_drop: SPI_connect returned %d",
             result);

    /* Execute the query */
    result = SPI_execute(query, true, 0);
    if (result != SPI_OK_SELECT)
        ELOG(ERROR, "pgaudit_ddl_drop: SPI_execute returned %d",
             result);

    /* Iterate returned rows */
    spiTupDesc = SPI_tuptable->tupdesc;
    for (row = 0; row < SPI_processed; row++)
    {
        HeapTuple    spiTuple;

        spiTuple = SPI_tuptable->vals[row];

        auditEventStack->auditEvent.objectType =
            SPI_getvalue(spiTuple, spiTupDesc, 1);
        auditEventStack->auditEvent.objectName =
            SPI_getvalue(spiTuple, spiTupDesc, 2);

        auditEventStack->auditEvent.logged = false;
        log_audit_event(auditEventStack);
    }

    /* Complete the query */
    SPI_finish();

    MemoryContextSwitchTo(contextOld);
    MemoryContextDelete(contextQuery);

    /* No longer in an internal statement */
    internalStatement = false;

	PGA_FUNCTION_TRACE("OUT");
    PG_RETURN_NULL();
}

/*
 * Define GUC variables and install hooks upon module load.
 */
void
_PG_init(void)
{
    MemoryContext contextOld;

    /* Be sure we do initialization only once */
    static bool inited = false;

    if (inited)
        return;

    /* Must be loaded with shared_preload_libaries */
    if (!process_shared_preload_libraries_in_progress)
        ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                errmsg("pgaudit must be loaded via shared_preload_libraries")));

    /* Define pgaudit.config_file */
    DefineCustomStringVariable(
		"pgaudit.config_file",
		"Specifies the file path name for pgaudit configuration.",
        NULL,
		&config_file,
		"",
		PGC_POSTMASTER,
		GUC_NOT_IN_SAMPLE,
		NULL, NULL, NULL);

    /*
     * Install our hook functions after saving the existing pointers to
     * preserve the chains.
     */
    next_ExecutorStart_hook = ExecutorStart_hook;
    ExecutorStart_hook = pgaudit_ExecutorStart_hook;

    next_ExecutorCheckPerms_hook = ExecutorCheckPerms_hook;
    ExecutorCheckPerms_hook = pgaudit_ExecutorCheckPerms_hook;

    next_ProcessUtility_hook = ProcessUtility_hook;
    ProcessUtility_hook = pgaudit_ProcessUtility_hook;

    next_object_access_hook = object_access_hook;
    object_access_hook = pgaudit_object_access_hook;
    /* register emit_log_hook to handle CONNECTION events. */
    next_emit_log_hook = emit_log_hook;
    emit_log_hook = pgaudit_emit_log_hook;
    
    /* register ExecutorEnd_hook for SESSION-AUDIT-LOG Rules execution timing */
    next_ExecutorEnd_hook = ExecutorEnd_hook;
    ExecutorEnd_hook = pgaudit_ExecutorEnd_hook;

    /* register ClientAuthentication_hook to debug the timing it called */
    next_ClientAuthentication_hook = ClientAuthentication_hook;
    ClientAuthentication_hook = pgaudit_ClientAuthentication_hook;

    /*
     * Allocate Context for the SESSION-AUDIT-LOG data collection.
     *
     * Data area is once allocated in this context are permanent, and never be
     * free. These area can be static, but the max length of these can't fixed.
     */
    contextAuditPermanent = AllocSetContextCreate(CacheMemoryContext,
        	                                 "pgaudit permanent context",
        	                                 ALLOCSET_DEFAULT_MINSIZE,
        	                                 ALLOCSET_DEFAULT_INITSIZE,
        	                                 ALLOCSET_DEFAULT_MAXSIZE);
    contextOld = MemoryContextSwitchTo(contextAuditPermanent);

 	/* Apply the locale to the messages those emit_log_hook() handles. */
    pgaudit_initMessages();

    /* init the Audit Data Field */
    pgaudit_initItems(true);

    /* Deploy the audit configlation from config_file. */
    pgaudit_parseConfiguration( config_file );

    MemoryContextSwitchTo(contextOld);

    /*
     *  Set ON to Log_connections and Log_disconnections to get timing.
     *  And keep old setting to recover edata at emit_log_hoock.
     */
    saveLogConnections = Log_connections;
    Log_connections = true;
    saveLogDisconnections = Log_disconnections;
    Log_disconnections = true;
    saveLogReplicationCommands = log_replication_commands;
    log_replication_commands = true;

     /* Log that the extension has completed initialization */
     ereport(LOG, (errmsg("pgaudit extension initialized")));

    /* Log that the extension has completed initialization */
    ereport(LOG, (errmsg("pgaudit extension initialized")));

    /* Start pgaudit_emit_log_hook. */
    isPGinitDone = true;
    inited = true;
}
