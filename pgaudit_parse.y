/* 
 * pgaudit_parse.y
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * Parse pgaudit configuration file.
 *
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit_parse.y
 */

%{

#include <stdio.h>						  
#include <string.h>
#include "pgaudit.h"
#include "pgaudit_parse.h"
#include "pgaudit_parseConfigurations.h"
#define YYDEBUG 0	   /* debug mode 1 */
#define YYERROR_VERBOSE /* parser message verbose. */

static char  pgaudit_rule_creating = 0; /* 0: not, 1: creating  rule */

extern int  yylexlinenum;  /* Global variables that exist in pgaudit_scan.c  */
extern char *yytext;	   /* current token */

extern char* config_file;

/* extern paser functoins */
extern int yyerror(const char *message);
extern int yylex(void);

%}

/* Keywords and reserved words */

%union {
	int  bool_val;
	int  int_val;
	char str_val[4096];
	char name[128];
}

%token NONZERO
%token DIGIT
%token EXPONENT

%token <str_val>BOOLEAN
%token <str_val> INTEGER
%token <str_val> LITERAL
%token NEWLINE

%token SECTION
%token OUTPUT_SECTION_NAME
%token OPTIONS_SECTION_NAME
%token RULE_SECTION_NAME
%token <str_val> FIELD_OUTPUT
%token <str_val> FIELD_OPTIONS
%token <str_val> FIELD_FORMAT
%token <str_val> FIELD_FILTER
%token KEYWORDS
%token IDENTIFIER
%token WSPCE
/* Single Quote */
%token SQT
/* NOT Single Quote */
%token NQT
/* Inner literal Single Quote */
%token IQT

%token START_SECTION
%token END_SECTION
%token <str_val> EQ_OPERATOR
%token <str_val> NE_OPERATOR
%token <str_val> OPERATOR

%type  <str_val> OUTPUT_SECTION_NAME OPTIONS_SECTION_NAME RULE_SECTION_NAME 
%type  <str_val> START_SECTION END_SECTION
%type  <str_val> NEWLINE


%%

config : 
	   | output_section 
	   | options_section 
	   | rule_section_list
	   | output_section options_section 
	   | output_section rule_section_list 
	   | options_section rule_section_list
	   | output_section options_section rule_section_list 
	{ 
	}
	;


/* output section */
output_section : OUTPUT_SECTION_NAME START_SECTION output_line_list END_SECTION
	{ 
	}
	;

output_line_list : output_line 
			| output_line_list output_line
	{
	}
	;

output_line : output_line_literal
			| output_line_integer
			| output_line_boolean
	{
	}
	;

output_line_literal : FIELD_OUTPUT EQ_OPERATOR LITERAL 
	{
		elog(DEBUG2, "output_line_literal,$1=%s,$2=%s,$3=%s", $1, $2, $3);
		pgaudit_deploySyslogOption( $1, $3 );
	}
	;

output_line_integer : FIELD_OUTPUT EQ_OPERATOR INTEGER
	{
		elog(DEBUG2, "output_line_integer,$1=%s,$2=%s,$3=%s", $1, $2, $3);
		pgaudit_deploySyslogOption( $1, $3 );
	}
	;

output_line_boolean : FIELD_OUTPUT EQ_OPERATOR BOOLEAN
	{
		elog(DEBUG2, "output_line_boolean,$1=%s,$2=%s,$3=%s", $1, $2, $3);
		pgaudit_deploySyslogOption( $1, $3 );
	}
	;

/* options section */
options_section : OPTIONS_SECTION_NAME START_SECTION options_line_list END_SECTION
	{ 
	}
	;

options_line_list : options_line 
				  | options_line_list options_line
	{
	}
	;

options_line : options_line_literal
			 | options_line_integer
			 | options_line_boolean
	{
	}
			 ;

options_line_literal : FIELD_OPTIONS EQ_OPERATOR LITERAL
	{
		elog(DEBUG2, "options_line_literal,$1=%s,$2=%s,$3=%s", $1, $2, $3);
		pgaudit_set_options( $1, $3 );
	} 
			;

options_line_integer: FIELD_OPTIONS EQ_OPERATOR INTEGER
	{
		elog(DEBUG2, "options_line_integer,$1=%s,$2=%s,$3=%s", $1, $2, $3);
		pgaudit_set_options( $1, $3 );
	} 
			;

options_line_boolean : FIELD_OPTIONS EQ_OPERATOR BOOLEAN
	{
		elog(DEBUG2, "options_line_boolean,$1=%s,$2=%s,$3=%s", $1, $2, $3);
		pgaudit_set_options( $1, $3 );
	} 
			;

rule_section_list : rule_section
				  | rule_section_list rule_section
	{
	}
			 ;

/* rule section */
rule_section : rule_section_with_filter
			 | rule_section_format_only
	{ 
	}
	;

rule_section_with_filter : RULE_SECTION_NAME START_SECTION format_line filter_line_list END_SECTION
	{ 
		pgaudit_rule_creating = 0; /* clear rule creating */
	}
	;

rule_section_format_only : RULE_SECTION_NAME START_SECTION format_line END_SECTION 
	{ 
		pgaudit_rule_creating = 0; /* clear rule creating */
	}
	;

format_line : FIELD_FORMAT EQ_OPERATOR LITERAL 
	{ 
		elog(DEBUG2, "format_line,$1=%s,$2=%s,$3=%s,pgaudit_rule_creating=%d", $1, $2, $3, pgaudit_rule_creating);
		if (pgaudit_rule_creating == 0) {
			pgaudit_deployRules("rule", $2, NULL);
			elog(DEBUG2, "format_line,create rule");
			pgaudit_rule_creating = 1; /* set rule creating */
		} 
		pgaudit_deployRules($1, $2, $3);
		elog(DEBUG2, "format_line,pgaudit_deployRules() called");
	}
	;

filter_line_list : filter_line
				 | filter_line_list filter_line
	{ 
	}
	;

filter_line : filter_line_literal
			| filter_line_integer
			| filter_line_boolean
	{ 
	}
	;

filter_line_literal : FIELD_FILTER EQ_OPERATOR LITERAL
	{
		pgaudit_deployRules($1, $2, $3);
	};

filter_line_literal : FIELD_FILTER NE_OPERATOR LITERAL
	{
		pgaudit_deployRules($1, $2, $3);
	};

filter_line_integer : FIELD_FILTER EQ_OPERATOR INTEGER
	{
		/* NOP */
	};

filter_line_boolean : FIELD_FILTER EQ_OPERATOR BOOLEAN
	{
		/* NOP */
	};

%%

/*
 * yyerror()
 * output parse error.
 */
int yyerror(const char *message)
{
	ereport(WARNING,
		(errcode(ERRCODE_SUCCESSFUL_COMPLETION),
		errmsg("Configuration file (%s) parse error at line %5d. current token(%s), (%s)",
			config_file, yylexlinenum, yytext, message)));
  return yylexlinenum;
}
 
#ifdef BISON_UNIT_TEST
void main(int argc, char **argv)
{
  FILE *fp; 
  yydebug=0; 
  printf("yyparse start\n");

  if(argc > 1)
	if ((fp = fopen(argv[1], "r")) == NULL) {
		fprintf(stderr, "open error, filename=%s\n", argv[1]);
		return;
	}

  yyset_in(fp);
  yyparse();	   /* parse configuration file. */
  printf("yyparse end\n");
}
#endif
