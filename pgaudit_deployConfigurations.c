/*
 * pgaudit_deployConfigrations.c
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * Backend functions for parse pgaudit configration. 
 * These deploy all paramaters from sections, into internal structures.
 *
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit_deployConfigrations.c
 */

#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

/* =======================================================================
 * Deploy paramaters of output section into Logger structure.
 *
 * Entry Point:
 *   void pgaudit_deploySyslogOption(char *name, char *literal);
 */
#define SYSLOG_NAMES
#include <syslog.h>

#include "pgaudit.h"

/* 
 * Code list from syslog.h
 *
 * This code is deeply dipends on <syslog.h> and followngs.
 * This must be rebuild when syslog.h and follwongs.
 *
 * 
 * at syslog.h
 *
 * #define SYSLOG_NAMES 
 * 	typedef struct _code {
 *         char    *c_name;
 *         int     c_val;
 *  } CODE;
 * 
 * CODE facilitynames[]=={,,,,{NULL,-1}};
 * CODE prioritynames[]=={,,,,{NULL,-1}};
 * CODE optionflagnames[] ... not defined, anyway.
 * #endif
 */

static const CODE Optionflagnames[] =
    {
        {"pid", 	LOG_PID},
        {"cons",	LOG_CONS},
        {"odelay",	LOG_ODELAY},
        {"ndelay",	LOG_NDELAY},
        {"nowait",	LOG_NOWAIT},
        {"perror",	LOG_PERROR},
        {NULL	 ,  -1}
    };

/*
 * CODE list for elog level 
 *
 */

static const CODE ElogLevels[] =
    {
        { "DEBUG5",		DEBUG5 },
        { "DEBUG4",		DEBUG4 },
        { "DEBUG3",		DEBUG3 },
        { "DEBUG2",		DEBUG2 },
        { "DEBUG1",		DEBUG1 },
        { "LOG",		LOG  },
        { "COMMERROR",	COMMERROR },
        { "INFO",		INFO },
        { "NOTICE",		NOTICE },
        { "WARNING",	WARNING },
#ifdef WIN32
        { "PGERROR",	PGERROR },
#endif
        { NULL,			-1}
    };

static const CODE LoggerSelect[] =
    {
        { "SERVERLOG",	(int) pgaudit__serverlog },
        { "SYSLOG", 	(int) pgaudit__syslog },
        { NULL,			-1}
    };

/*
 * get a code by neme from a CODElist.
 * returns plus code or -1(not found).
 */
static int pgaudit_nameToCode(const CODE *list, const char *name)
{
    char Name[12];
    int	 i,j=0;


    for (i=0; name[i]!='\0'; i++) 
        if ( (name[i]!='\'') && (name[i]!='\t') && (name[i]!=' ') )
        {
            Name[j++]=toupper(name[i]);
            if (10 < j) 
                return -1;
        }
    Name[j]='\0';

    for (i=0 ; list->c_name!=NULL; list++ ) 
        if (!strncmp(Name, list->c_name,12)) 
            break;

    return list->c_val;
}
/*
 * get a code by neme from a CODElist.
 * returns plus code or -1(not found).
 */
static int pgaudit_syslogNameToCode(const CODE *list, const char *name) 
{
    char Name[12];
    int	 i,j=0;

    for (i=0; name[i]!='\0'; i++) 
        if ( (name[i]!='\'') && (name[i]!='\t') && (name[i]!=' ') )
        {
            Name[j++]=tolower(name[i]);
            if (10 < j) 
                return -1;
        }
    Name[j]='\0';

    if (strncmp(Name,"log_",4))
        return -1;

    for ( ; list->c_name!=NULL; list++ ) 
        if (!strncmp(&Name[4],list->c_name,12)) 
            break;

    elog( DEBUG3, "		name=%s:code=%d\n", name, list->c_val);
    return list->c_val;
}
/*
 * get a code form option list such as 'LOG_NDELAY | LOG_PID'
 * returns plus code or -1(not found).
 */
static int pgaudit_syslogOptionNameListToCode(const CODE *list, const char *name)
{
    char Name[128];
    char *N=Name;
    int	 r=0;

    strncpy(Name,name,127);

    N=strtok( N, "'/ /\t/|");
    while(N != NULL) { 
        r=r|pgaudit_syslogNameToCode(Optionflagnames, N);
    	if (r<0) {
       		ereport(WARNING,
                (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
                errmsg("unknown names:%s", name)));
            return r;
        }
        N=strtok( NULL, "'/ /\t/|");
    }
    return r;
}

/*
 * pgaudit_deploySyslogOption
 *
 *  Deploy each Output Option line into the LoggerOption structure.
 *	If a value is not accepable, it is egnored, noting changes.
 *
 *  Input:
 *      name     : lefthands of the line. "logger","pathlog", and other options.
 *      literal  : righthands of the line.
 *
 *  Output:
 *      noting   : deploy into pgauditLoggerOption.
 *
 *  Caution: 
 *  	this code edits the input literal, as strtok does.
 *      in case of pathlog the literal should be keeped by caller.
 */
static bool isInASection = true;
void pgaudit_deploySyslogOption(char *name, char *literal)
{
    pgauditLogger *X = &pgauditLoggerOption;
    int r=0;
    static bool isFirst = true;

    if (isFirst)
    {
        ereport(CONFNORMAL, 
            (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
            errmsg("pgaudit: output {")));
        isFirst = false;
        isInASection = true;
    }

    if (name == NULL) 
       elog(FATAL, "Invalid name(null).");


    if ( !strcmp(name, "logger") )
    {
        r = pgaudit_nameToCode(LoggerSelect, literal);
        if ( r >= 0 ) 
            X->logger 	= r;
    }
    else if ( !strcmp(name, "option") )
    {
        r = pgaudit_syslogOptionNameListToCode(Optionflagnames, literal); 
        if ( r >= 0 ) 
            X->option 	= r;
    }
    else if ( !strcmp(name,	"pathlog") )
    {
        char *p = palloc(strlen(literal));
        strcpy(p, literal);
        p[strlen(p)-1] = '\0';
        X->pathlog 	= &p[1];
    }
    else if ( !strcmp(name,	"ident") )
    {
        char *p = palloc(strlen(literal));
        strcpy(p, literal);
        p[strlen(p)-1] = '\0';
        X->ident 	= &p[1];
    }
    else if ( !strcmp(name,	"facility" ) )
    {
        r = pgaudit_syslogNameToCode(facilitynames, literal);
        if ( r >= 0 )
            X->facility = r;
    }
    else if ( !strcmp(name,	"level" ) )
    {
        r = pgaudit_nameToCode(ElogLevels, literal);
        if ( r >= 0 )
            X->level	= r;
    }
    else if ( !strcmp(name,	"priority" ) )
    {
        r = pgaudit_syslogNameToCode(prioritynames, literal);
        if ( r >= 0 )
            X->priority = r;
    }
    else if ( !strcmp(name, "maxlength") )
    {
        r = atoi(literal);
        if ( r >= 0) 
            X->maxlength= r;
    }
    else 
        r = -1;

    if ( r < 0 )
        ereport(CONFIGNORE, 
            (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
            errmsg("pgaudit:      %s = %s => error,ignored", name, literal)));
    else
        elog(CONFNORMAL, "pgaudit:      %s = %s (%d)", name, literal, r);

    return;
}

/* =======================================================================
 * Deploy paramaters of rule sections (format and filters) into structures.
 *
 * Entry Point:
 *   void pgaudit_deployRules(char *name, char *operator, char *literal)
 */

/* error indicator. */

static bool isError = false;

/* pgaudit_nameToItem */ 
static enum pgauditItem pgaudit_nameToItem( const char *name )
{
    int i;
    for ( i=2; pgauditDataIndexes[i].item != null_item_i; i++ ) 
        if (!strcmp( pgauditDataIndexes[i].name, name ) )
            return pgauditDataIndexes[i].item;
    return null_item_i;
}


/* table of the logline prefix and the pgauditItem */
static const struct {
    char 				prefix;
    enum pgauditItem	item;
} pgauditLoglinePrefix[] = {
    { 't', timestamp_i },
    { 'p', pid_i },
    { 'd', database_i },
    { 'i', command_tag_i },
    { 'a', application_name_i },
    { 'v', virtual_xid_i },
    { 'h', remote_host_i },
    { 'u', user_i },
    { '%', format_text_i },
    { '\0' , format_text_i }
};

/*
 * deployFormat:
 *
 * 	extracting the labels and items from the format.
 */
static pgauditPrintIndex *pgaudit_deployFormat(const char *format)
{
    int i=0;
    char *b,*p;
    pgauditPrintIndex *printIndexes, *d;

    if ( *format != '\'' || format[strlen(format)-1] != '\'')
    {
        isError = true;
        ereport(WARNING,
            (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
            errmsg("Internal error: format style error %s %s",format,":quote\n" )));
        return  NULL;
    }

    p=(char*)palloc(strlen((char*)format));

    strcpy(p, format);
    *p=p[strlen(p)-1] = '\0';
    b=++p;
    
    while (*p!='\0') {
        if (*p=='%') 
            i++;
        p++;
    }
    p=b;

    printIndexes = d = (pgauditPrintIndex*) palloc(sizeof(pgauditPrintIndex) * (i+1));

    memset(d, 0, sizeof(pgauditPrintIndex) * (i+1));
    while (1)
    {
        b = p;
        p = strstr(p, "%");
        if ( p == NULL ) 
        {
            /* text after the last %item */
            d->text = b;
            d->item = null_item_i;
            break;
        }
        else 
        {
            if (*p == '%')
            {
                /* set printLabel */
                *p='\0';
                d->text = b;
                p++;
            }
            else
            {
                /* No Lavel between %items */
                d->text = NULLSTRING;
            }
        
            /* serch an item from pgauditDataIndexes by name */
            for (i=0; pgauditDataIndexes[i].name[0] != '\0'; i++)
                if ( !strncmp(p, pgauditDataIndexes[i].name, strlen(pgauditDataIndexes[i].name)))
                    break;

            if ( pgauditDataIndexes[i].name[0] == '\0' )
            {
                /* serch an item from pgauditLoglinePrefix by name */
                for (i=0; pgauditLoglinePrefix[i].prefix != '\0'; i++)
                    if ( *p == pgauditLoglinePrefix[i].prefix )
                        break;

                if ( pgauditLoglinePrefix[i].prefix == '\0' )
                {
                    ereport(WARNING, 
                        (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
                        errmsg("error: unknown format item in %s:%%%s", format, p)));
                    d->item = format_text_i;
                }
                else
                {
                    d->item = pgauditLoglinePrefix[i].item;
                    p++;
                }
            }
            else
            {
                d->item = pgauditDataIndexes[i].item;
                p += strlen(pgauditDataIndexes[i].name);
            }
        }
        d++;
    }
    return (printIndexes);
}


/*
 * deployNames:
 * 
 * 	extracting the labels and items from the literal.
 *
 * 	input
 *	  literal : quauted strins, 
 *		neme list delimited by comma with blanks and tabs.
 *		Ex: ' name1,name2  , name3'
 *
 * 	output
 *	  retuens an argment list : 
 *		An argv style name list, terminated by NULL.
 *		Each name in the list is added two blanks, one is before the name, 
 *		and the another is after the name.
 * 		If a % is in the top of a name, this function will omit the % and 
 * 		the blank before the name. And if a % is in the tail of a name, 
 * 		this function will omit the % and the blank after the name. % in 
 * 		the middle of a name are some parts of the name.
 * 		Ex: 'na%e' => " na%e " , '%%ame' => "%ame " , 'name%'=> " name"
 *
 */
static bool pgaudit_checkNameString(char *str, int argc);
static void pgaudit_deployNamesBody(char *str, char *names, 
                        			int argc, char *argv[]);
static char **pgaudit_deployNames(char *literal);


static bool pgaudit_checkNameString(char *str, int argc)
{
    int i=1,j=1,k=1;
    char *s=str;

    /* plane literal */
    for (s=str; *s!='\0'; s++) switch(*s)
    {
    case '\'':
        if ( ( s==str ) || ( *(s+1) =='\0' ) )
            continue;
        else 
            return false;		/* Internal Error */
    case ',':
        return false;			/* too many comma */
    case ' ':
    case '\t':
        continue;
    default:
        /* name */
        for (j=1; j>0; s++) switch(*s)
        {
        case '\0':
            return false;		/* Intenal Error*/
        case '\'':
            return ( (*(s+1)=='\0') && (i==argc) );
        case ',':
            i++;
            j=0;  				/* exit middle loop */
            break;				/* break switch */
        case ' ':
        case '\t':
            /* after name */
            for (k=1; k>0; s++) switch(*s)
            {
            case '\0':
                return false;	/* internal error */
            case '\'':
                return ( (*(s+1)=='\0') && (i==argc) );
            case ',':
                i++;
                j=0;  			/* exit middle loop */
                k=0;  			/* exit lower loop */
                break;			/* break switch */
            case ' ':
            case '\t':
                continue;
            default:
                return false;	/* comma requested */
            }
        default:
            break;
        }
    }
    return true;
}
    
static void pgaudit_deployNamesBody(char *str, char *names, int argc, char *argv[])
{
    int i=1;
    char *p=names,*s=str;

    for (i=0; i<argc; i++)
    {
        argv[i] = p;
        s=strtok(s, "', \t");
        if ( !s ) 
            break;
        if ( *s != '%' )
        {
            *p = ' ';
            p++;
        }
        else
            s++;
        strcpy(p, s);
        if ( p[strlen(p)-1] == '%' )
            p[strlen(p)-1] = '\0';
        else
            strcpy( &p[strlen(p)], " ") ;
        p += strlen(p)+1;
        s += strlen(s)+1;
    }
    argv[i] = NULL;

    return;
}

static char **pgaudit_deployNames(char *literal)
{

    char *names, *str;
    int i = 0, l = strlen(literal);
    int c = 0;
    char **args;

    for (i=0;i<l;i++)
        if( literal[i] == ',') 
            c++;

    if( ( literal[0] != '\'') || (literal[l-1] != '\'') )
    {
        isError = true;
        elog( WARNING, 
            "internal error: single quart was expected in [%s]."
            " The filter line was ignored.", 
            literal);
        return NULL;
    }

    if ( !pgaudit_checkNameString( literal, c+1 ) )
    {
        isError = true;
        ereport(WARNING, 
            (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
            errmsg( "format error in [%s]. The filter line was ignored.",
                literal)));
        return NULL;
    }

    str   = palloc( strlen(literal) + 1 );
    names = palloc( strlen(literal) + (c+1)*2+1 );
    args  = palloc( sizeof(char*) * (c+2) );

    strcpy(str, literal);
    
    pgaudit_deployNamesBody(str, names, c+2, args);
    if (!str)
        pfree( str );
    return args;
}

/*
 * timestampToInt:
 * 
 * yyThis function converts the timestamp string (hh:mm:dd) to the cumulative 
 * number of seconds of a day.
 *
 * input
 * 		timestamp : "hh:mm:ss"
 *
 * output
 * 		returns a number :  ((((hh*60)+mm)*60+ss))
 *
 */
static int  pgaudit_timestampToInt(const char *timestamp);

#undef  pgauditerror
#define pgauditerror(fmt,ptr) {\
    isError = true;\
    return (-1);\
}
/*	ereport(WARNING, \
 * 			(errcode(ERRCODE_SUCCESSFUL_COMPLETION), \
 *			errmsg( (fmt), (ptr) ))); \
 */
static int pgaudit_timestampToInt(const char *timestamp)
{
    char *p, *q;
    int hh=0,mm=0,ss=0;
    char str[9];

    /* 
     * The length and Format of the timestamp is as follws:
     * - Fixed at 8 letters and hh:mm:ss format.
     * - Only Numbers and ":" are acceptable.
     * - NULL terminater does not required.
     */

    strncpy(str, timestamp, sizeof(str));
    str[8]='\0';

    if (    strstr(str, " ") || strstr(str, "+") || strstr(str, "-") 
        || (strlen(str)!=8) || (str[2]!=':') || (str[5]!=':') )
        pgauditerror("error: format error at timestamp[%s]", str);

    hh=strtol( str, &p, 10);
    if ( (str==p) || (*p!=':') || (hh<0) || (23<hh) )
        pgauditerror("error: format error at timestamp[%s]", str);

    mm=strtol( p+1 , &q, 10);
    if ( (p+1==q) || (*p!=':') || (mm<0) || (59<mm) )
        pgauditerror("error: format error at timestamp[%s]", str);

    ss=strtol( q+1, &p, 10);
    if ( (q+1==p) || (ss<0) || (59<ss) )
        pgauditerror("error: format error at timestamp[%s]", str);

    elog( DEBUG3, 
          "pgaudit_timestampToInt[%s]::hh=%d,mm=%d,dd=%d => %d\n", 
          str,hh,mm,ss, ((hh*60)+mm)*60+ss );

    return (((hh*60)+mm)*60+ss);
}

#define TSSIZE strlen("hh:mm:ss")
#define TLSIZE strlen("hh:mm:ss-hh:mm:ss")

static const int pgauditFullTime[4]= {0, (24*60*60-1), -1, -1};
static int pgauditNullInt = -1;

/*
 * deployTimestamps:
 *
 *  input
 *      str : A sequence of the timestamps such as follws:
 *          ' hh:mm:ss-hh:mm:ss , hh:mm:ss-hh:mm:ss '
 *
 *  output
 *      returns a sequence of second of the day, integer terminated by -1.
 *
 */
static int *pgaudit_deployTimestamps(const char *str);
static bool pgaudit_deployTimestampsBody(const char *str, int *secList);

#undef pgauditerror

#define pgauditerror(fmt,ptr) { \
    isError = true;\
    return (false);\
}
static bool pgaudit_deployTimestampsBody(const char *str, int *secList)
{
    char *p = (char*) str+1;
    int	 r, *d = secList;

    while (1) 
    {
        /* Clock-In time */
        r = pgaudit_timestampToInt( p );
        if ( r < 0)
            return false;
        *d++ = r;

        /* separator */
        p += TSSIZE;
        if ( *p != '-' )
            pgauditerror("error in timestamps style %s",str);
        p++;

        /* Clock-Out time */
        r = pgaudit_timestampToInt( p );
        if ( r < 0)
            return false; 
        if ( *(d-1) >= r )
            pgauditerror("error at timestamps values %s",str);
            
        *d++ = r;

        /* next Clock or end of the list */
        p += TSSIZE;
        while ( *p == ' ' || *p == '\t') p++;
        if ( *p == '\'') 
        {
            *d++ = -1;
            *d   = -1;
            return true; 
        }
        if ( *p != ',') 
            pgauditerror("error in timestamps style %s",str);
        p++;
        while ( *p == ' ' || *p == '\t') p++;
    }
}
#undef pgauditerror

#define pgauditerror(fmt,ptr) { \
    isError = true;\
    elog( WARNING, (fmt), (ptr) ); \
    return (&pgauditNullInt);\
}
static int *pgaudit_deployTimestamps(const char *str)
{
    int i=0, c=0, *secList = NULL;

    if (str[0] != '\'')
        pgauditerror("internal error: format error at timestamp[%s]", str);

    for (i=1;str[i]!='\'';i++)
        if (str[i]==',') 
            c++;
        else if ( str[i]=='\0' )
            pgauditerror("internal error: format error at timestamp[%s]", str);

    if ( i == ( TLSIZE*(c+1) + strlen(",")*c) )
    {
        ereport(WARNING,
            (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
            errmsg( "error: format error at timestamp[%s]", str)));
        isError = true;
        return (&pgauditNullInt);
    }

    secList = (int*) palloc( sizeof(int)*2*(c+1+1) );
    if ( !pgaudit_deployTimestampsBody( str, secList ) )
    {
        pfree(secList);
        secList = (int*) NULL;
        return (&pgauditNullInt);
    }
    return (secList);
}
#undef pgauditerror

/*
 *	deployRules:
 *
 *	Deploy a format line or a filter line into the chane of Rule structures.
 *
 *	input
 *		name	 : lefthands of the line. "rule","format", and filter items.
 *		operator : "=" or "!"
 *		literal	 : righthands of the line.
 *
 *	output
 *		(void)	 : (Rule structure, insaide.)
 *
 */
static pgauditRule *R	= NULL;
static pgauditRule **N 	= &pgauditRules;
static pgauditFilter *F	= NULL;
static pgauditFilter **X= NULL;
void pgaudit_deployRules(char *name, char *operator, char *literal)
{ 
    elog(DEBUG3, "===============deployRules:accept[%s %s %s]",name,operator,literal);

    isError = false;
    if ( !strcmp(name, "rule") )
    {
        R = palloc(sizeof(pgauditRule));
        R->filters		= NULL; 	/* NULL : output all logs */
        R->format 		= NULL; 	/* reservd */
        R->printIndex 	= NULL; 	/* NULL : use pgauditDefaultPrintIndex */;
        R->next=NULL;				/* NULL : end of Rules */
        *N = R;
        N = &( R->next );
        X = &( R->filters );
        elog(CONFNORMAL, "pgaudit: }");
        elog(CONFNORMAL, "pgaudit: rule {");
        return;
    }
    else if ( !strcmp(name, "format") )
        if ( !R )
            elog(WARNING, "Internal Error: format whithout rule ! %s", literal);
        else
            R->printIndex = pgaudit_deployFormat(literal);
    else
    {
        if ( !R )
            elog(WARNING, "Internal Error: filter whithout rule ! %s", literal);
        else 
        {
            F = palloc(sizeof(pgauditFilter));
            F->lefthand = pgaudit_nameToItem( name );
            F->operator = (*operator=='=') ? operator_equal : operator_notequal;
            if ( F->lefthand == timestamp_i )
                F->righthand.numbers = pgaudit_deployTimestamps( literal );
            else
             	F->righthand.roster = pgaudit_deployNames( literal );
            F->next = NULL;
            *X = F;
            X = &( F->next );
        }
    }

    if (isError)
        ereport(CONFIGNORE,
            (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
            errmsg("pgaudit:      %s %s %s => error,ignored", 
                name, operator, literal)));
    else
        elog(CONFNORMAL, "pgaudit:      %s %s %s", name, operator, literal);

    return;
}

/* =======================================================================
 *	Deploy paramaters of options section into audit controle valiables.
 *
 *	Entry Point:
 *    pgaudit_set_options(char* name, char* value) 
 */

/* audit controle valiables */
extern bool	auditLogCatalog;
extern int	auditLogLevel;
extern bool	auditLogParameter;
extern bool	auditLogStatementOnce;
extern char* auditRole;


/*
 * strlowercmp:
 *
 *  case-insensitive compare.  
 *  returns 1(s1 is bigger than s2), -1(s2 is bigger than s1), or 0(equal)
 */
static int
strlowercmp(char* s1, char* s2) {
    while (1) 
    {
        if      ( tolower(*s1) > tolower(*s2) ) 
            return 1;
        else if ( tolower(*s1) < tolower(*s2) )
            return -1;
        else if ( *s1 == '\0' ) 
            return 0;
        s1++, s2++;
    }
}

/* 
 * str2bool:
 *
 * convert from string representation boolean into bool type value. 
 * returns boolean.
 */
static bool
str2bool(char* value, bool default_value) {
    if ( !strlowercmp(value, "true") || !strlowercmp(value, "on") ) 
        return true;
    else if ( !strlowercmp(value, "false") || !strlowercmp(value, "off") ) 
        return false;

    isError = true;
    return default_value;
}

/*
 * setRole:
 *
 * allocates a string for role name, then copy.
 * returns pointer alocated.
 */
static char*
setRole(char* leteral_value) {
    char* value = NULL;

    value = palloc(strlen(leteral_value) - 1);

    /* remove single quotes */
    strncpy(value, leteral_value + 1, strlen(leteral_value) - 1);
    *(value + (strlen(leteral_value) - 2)) = '\0';

    return pstrdup(value);
}

/*
 *	set_options:
 *
 *	deploy paramaters of options section into audit controle valiables.
 *	if a value is not accepable, it is egnored, noting changes.
 *
 *	input
 *		name	 : keyword in the options section.
 *		value	 : string representation boolean or role name.
 *
 *	outpust
 *		(void)	 : (audit controle valiables, pgaudit insaide.)
 *
 */
void
pgaudit_set_options(char* name, char* value) 
{
    static bool isFirst = true;

    isError = false;

    if (isFirst)
    {
        if (isInASection)
            ereport(CONFNORMAL, 
                (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
                errmsg("pgaudit: }")));
        ereport(CONFNORMAL, 
            (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
            errmsg("pgaudit  options {")));
        isFirst = false;
        isInASection = true;
    }

    if (name == NULL) 
       elog(FATAL, "Invalid name(null).");

    if 		( !strlowercmp(name, "log_catalog") )
        auditLogCatalog = str2bool(value, auditLogCatalog);
    else if ( !strlowercmp(name, "log_level") ) 
    {
        int r = pgaudit_nameToCode(ElogLevels, value);
        if ( r >= 0 )
            auditLogLevel = r;
        else
            isError = true;
    } 
    else if ( !strlowercmp(name, "log_parameter") )
        auditLogParameter = str2bool(value, auditLogParameter);
    else if ( !strlowercmp(name, "log_statement_once") ) 
        auditLogStatementOnce = str2bool(value, auditLogStatementOnce);
    else if ( !strlowercmp(name, "role") ) 
        auditRole = setRole(value);
    else 
        isError = true;

    if (isError)
        ereport(CONFIGNORE, 
            (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
            errmsg("pgaudit:      %s = %s => error,ignored", name, value)));
    else
        elog(CONFNORMAL, "pgaudit:      %s = %s", name, value);

}

