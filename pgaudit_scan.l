/*
 * pgaudit_scan.l
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * Token scanner called from pgaudit_parse.y parser
 *
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit_scan.l
 */

%{
#include <stdio.h>
#include <stdlib.h>
int yylexlinenum = 1;
#include "pgaudit_parse.h"

#define copy_and_return(token_type) \
         { \
             strcpy(yylval.name,yytext);\
             return(token_type); \
         }

%}

%option noyywrap
%option nounput

%x COMMENT
%x LITERAL_STATUS

NONZERO         [1-9]
DIGIT           [[:digit:]]
EXPONENT        [eE](-|\+?){DIGIT}+
BOOLEAN         off|on|false|true|0|1

OUTPUT_SECTION_NAME  output
OPTIONS_SECTION_NAME options
RULE_SECTION_NAME    rule
SECTION_NAME    {RULE_SECTION_NAME}|{OUTPUT_SECTION_NAME}|{OPTIONS_SECTION_NAME}
FIELD_FORMAT    format
FIELD_OUTPUT    logger|pathlog|ident|option|facility|priority|level|maxlength
FIELD_OPTIONS   log_catalog|log_level|log_parameter|log_statement_once|role
FIELD_FILTER    timestamp|database|current_user|user|class|command_tag|object_type|object_id|application_name|command_result|remote_host|shutdown_status
KEYWORDS        {FIELD_FORMAT}|{FIELD_OUTPUT}|{FIELD_OPTIONS}|{SECTION_NAME}
INTEGER         -?{NONZERO}{DIGIT}*|0
IDENTIFIER      [_[:alpha:]][_[:alnum:]]*
EQ_OPERATOR     =
NE_OPERATOR     !
OPERATOR        {EQ_OPERATOR}|{NE_OPERATOR}
WSPACE          [[:blank:]]+
SQT             [']
NQT             [^']
IQT             [\\][']
START_SECTION   "{"
END_SECTION     "}"
NEWLINE         "\n"
LITERAL         .*
%%

<<EOF>>         return 0;
{INTEGER}       {
                    copy_and_return(INTEGER);
                }
{BOOLEAN}       {
                    copy_and_return(BOOLEAN);
                }
{OUTPUT_SECTION_NAME}  {
                    copy_and_return(OUTPUT_SECTION_NAME);
                }
{OPTIONS_SECTION_NAME}  {
                    copy_and_return(OPTIONS_SECTION_NAME);
                }
{RULE_SECTION_NAME}  {
                    copy_and_return(RULE_SECTION_NAME);
                }

{FIELD_OUTPUT}  {
                    copy_and_return(FIELD_OUTPUT);
                }
{FIELD_OPTIONS} {
                    copy_and_return(FIELD_OPTIONS);
                }
{FIELD_FORMAT}  {
                    copy_and_return(FIELD_FORMAT);
                }
{FIELD_FILTER}  {
                    copy_and_return(FIELD_FILTER);
                }

{EQ_OPERATOR}   {
                    copy_and_return(EQ_OPERATOR);
                }
{NE_OPERATOR}   {
                     copy_and_return(NE_OPERATOR);
                }
{IDENTIFIER}   {
                     copy_and_return(IDENTIFIER);
                }
{WSPACE}        ;
{START_SECTION} {copy_and_return(START_SECTION);}
{END_SECTION}   {copy_and_return(END_SECTION);}
{NEWLINE}       {yylexlinenum++; }

"#"            	BEGIN(COMMENT); yymore();
<COMMENT>"\n"   BEGIN(INITIAL); {yylexlinenum++; }
<COMMENT>[^\n]+ yymore();


{SQT}			BEGIN(LITERAL_STATUS);yymore();
<LITERAL_STATUS>{NQT}	yymore();
<LITERAL_STATUS>{IQT}	yymore();
<LITERAL_STATUS>{SQT}	{BEGIN(INITIAL); copy_and_return(LITERAL);}

.               {}

%%


#ifdef FLEX_UNIT_TEST
int main(int argc, char** argv)
{
  if(argc > 1)
    yyin = fopen(argv[1], "r");
  return yylex();
}

#endif
