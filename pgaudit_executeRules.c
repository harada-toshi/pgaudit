/*
 * pgaudit_executeRules.c
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * Execute all rules for SESSION-AUDIT-LOGGING.
 * Output a log to the logger specified.
 *
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit_executeRules.c
 */
#include <stdio.h>
#include <sys/time.h>
#include <stdbool.h>
#include <string.h>
#include <stdbool.h>
#include "pgaudit.h"
#include "pgaudit_syslog.h"

/*
 * Functions:
 * execute all rules for SESSION-AUDIT-LOGGING.
 *   pgaudit_executeRules()
 *     -> pgaudit_executeRule()
 *       -> pgaudit_isNameInRoster()
 *       -> pgaudit_isIntgerInInterval()
 *       -> pgaudit_outputLog()
 * 	 	   -> pgaudit_doOutput() 
 *           -> pgaudit_doOutputSyslog()
 *
 * output a log to the logger specified.
 *   pgaudit_doOutput() 
 *     -> pgaudit_doOutputSyslog()
 *
 */

/* 
 * pgaudit_isTargetInRoster:
 *  is the name in the roster ?
 *
 * input
 *  name : balanc delimited names. start and end by blanc.
 *  		names= " name1 name2 .... nameX ";
 *
 *  roster : names in argv style where:
 *  	    " name " : full mach 
 *  	    " name"  : left mach
 *  	    "name "  : right mach
 *  	    "name"   : part mach
 * output
 * 		returns true(at least one of the name is in the roster) or false.
 *
 */
static bool pgaudit_isNameInRoster(const char *names, char **roster)
{
    char	**r;
 
    for ( r=roster; *r>0; r++ ) 
        if ( strstr(names, *r) )
            return true;
    return false;
}
    
/* 
 * pgaudit_isTargetInInterval:
 *
 * evaluate timestamps by secofday.  is the target in the intervals ?
 *
 * input
 *		target    : second of day ( = hh*3600+mm*60+ss )
 *		intervals : pairs of integer (star and end), 
 * 			int	intervals[2][]= { 
 * 					{((hh*60+mm)*60+ss,((hh*60+mm)*60+ss}, ...
 * 					{-1.-1}
 * 				};
 *
 * output
 * 		returns true(the target is in the intervals) or false.
 */
static bool pgaudit_isIntgerInInterval(const int target, const int *intervals){
    int		i;

    for (i=0;intervals[i*2]>=0;i++)
        if ((target >= intervals[i*2]) && (target <= intervals[i*2+1])) 
            return true;
            
    return false;
}


#ifndef X
#define X pgauditLoggerOption
#endif

static void pgaudit_doOutputSyslog(char *mes) {
    int		c=0, n=0, l=strlen(mes);

#ifdef PGAUDIT_LOG_SEPALATE_AT_YN
    if ( *mes=='\0' ) 
            pgaudit_syslog(X.priority, "%s", " "); 
    else 
#endif 

    if ( X.maxlength > 0) 
    {
        while(1)
        {
            if (X.maxlength >= l-c) 
            { 
                pgaudit_syslog(X.priority, "%s", &mes[c]);
                break;
            }
            else
            {
                char keep;
    
                n = c + X.maxlength;
                keep = mes[n];
                mes[n] = '\0';
                pgaudit_syslog(X.priority, "%s", &mes[c]);
                mes[n] = keep;
            }
            c = n;
        }
    }
    else 
        pgaudit_syslog(X.priority, "%s", mes);
    return;
}

/*
 * outputLog:
 *
 * outputs a log to the logger spesifid.
 *
 * input 
 * 		message 
 *
 * output
 * 		void
 */ 
void pgaudit_doOutput(char *message) 
{
    if 		( pgauditLoggerOption.logger == pgaudit__serverlog )
    {
        extern int log_min_messages;
        extern int emitLogCalled;
        if ( isOutPutELOG(X.level,log_min_messages) ) 
        {
            emitLogCalled++;
            ereport( X.level, 
                    (errmsg("%s", message), 
                    errhidestmt(true), 
                    errhidecontext(true)) );
            emitLogCalled--;
        }
    }
    else if ( pgauditLoggerOption.logger == pgaudit__syslog )
    {
        pgaudit_openlog(X.ident, X.option, X.facility, X.pathlog);
        pgaudit_doOutputSyslog(message);

#ifdef PGAUDIT_LOG_SEPALATE_AT_YN
        /*
 	 	 * Omited code.
 	 	 * To separate the log in '\n'. 
     	 * If the escape sequence of \n(#012) appears in your log, check the
     	 *  configlations of your syslogd firat. 
     	 */
        {
            char *p,*q;
            q = message;
            while(1) 
            {
                p = strstr( q, "\n");
                if ( p == NULL )
                {
                    pgaudit_doOutputSyslog(q);
                    break;
                }
                *p = '\0';
                pgaudit_doOutputSyslog(q);
                q=p+1;
            }
        }
#endif 

        pgaudit_closelog();
    }
    else
    {
        ELOG(WARNING, "internal error: pgauditLoggerOption.logger = %x", X.logger);
    }

}

/*
 * outputLog:
 *
 * outputs a SESSION-AUDIT-LOG to logger spesifid with format spesifid.
 *
 * input 
 * 	 	printIndex	:Internal representation of the format specifieid.
 *
 * output
 * 	 	void
 */ 
static void pgaudit_outputLog(pgauditPrintIndex *printIndex)
{
    pgauditPrintIndex *pi=printIndex;
    StringInfoData	message; 

    /*
 	 * catalocation
 	 */
    initStringInfo(&message);

    if ( !pi ) 
        pi = (pgauditPrintIndex*) pgauditDefaultPrintIndex;

    for (;;pi++ )
    {
        /* print text before item */
        appendStringInfo(&message, "%s", pi->text);

        /* print item */
        if ( pgauditDataIndexes[pi->item].type == direct)
            appendStringInfo(&message, "%s", pgauditDataIndexes[pi->item].data.direct);
        else 
        {
            char *t;
            int   i;

            if ( 	pgauditDataIndexes[pi->item].type == fix )
                t = pgauditDataIndexes[pi->item].data.fix;
            else 
                t = pgauditDataIndexes[pi->item].data.flex->data;

            i = strlen(t)-1;
            t[i] = '\0';
            appendStringInfo(&message, "%s", &t[1]);
            t[i] = ' ';
        }
        if ( pi->item == null_item_i )
            break;
    } 

    /*
     * Do Output
     */
    pgaudit_doOutput(message.data);

    resetStringInfo(&message);
    return;
}


/*
 * executeRule:
 *
 * execute a rule for SESSION-AUDIT-LOGGING
 *
 * input 
 * 		 rule :Internal representation of the rule specifieid.
 *
 * output
 * 		 void (outputs at most one SESSION-AUDIT-LOG)
 */
static void pgaudit_executeRule(pgauditRule *rule)
{
    pgauditFilter	*filter;
    bool			 r=true;

    /*
 	 * Evaluete Rules
 	 */
    filter = rule->filters;
    while ( filter && r) 
    {
        if (filter->lefthand == null_item_i);			/* Do nothing */
        else if (filter->lefthand == timestamp_i)
            r = filter->operator 
                ^ pgaudit_isIntgerInInterval(
                    pgauditLogSecOfDay, 
                    filter->righthand.numbers); 
        else if (pgauditDataIndexes[filter->lefthand].type == fix)
            r = filter->operator 
                ^ pgaudit_isNameInRoster(
                    pgauditDataIndexes[filter->lefthand].data.fix, 
                    filter->righthand.roster);
        else
            r = filter->operator 
                ^ pgaudit_isNameInRoster(
                    pgauditDataIndexes[filter->lefthand].data.flex->data, 
                     filter->righthand.roster);

        ELOG(DEBUG3, 
            "pgaudit_executeRule:filter->lefthand=%d:filter->operator=%d:r=%d",
                        		 filter->lefthand,   filter->operator,   r );
        filter = filter->next;
    }

    if ( !r ) 
        return;

    pgaudit_outputLog(rule->printIndex);
    return;
}

/*
 * executeRules:
 *
 * execute all rules for SESSION-AUDIT-LOGGING
 *
 * input 
 * 		 void (extern pgauditRules, pgauditDataIndexes)
 *
 * output
 * 		 void (outputs SESSION-AUDIT-LOGs)
 */
void pgaudit_executeRules(void)
{
    pgauditRule *rule = pgauditRules;

    if (!rule)
        pgaudit_outputLog( NULL ); 
    while (rule)
    {
        pgaudit_executeRule(rule);
        rule = rule->next;
    }
    return;
}
