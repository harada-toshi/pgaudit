/*
 * pgaudit_parseConfigurations.c
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * This function group is one that is called from 
 * the action part of pgaudit configuration file parsing.
 *
 * IDENTIFICATION
 *           contrib/pgaudit_parseConfigurations.c
 */

#include <stdio.h>
#include <sys/stat.h>
#include "pgaudit.h"
#include "pgaudit_parse.h"

#include "pgaudit_parseConfigurations.h"

static char* getConfigurationString(char *path, int size) ;

/*
 * pgaudit_initConfiguration
 *
 * To initialize the setting information.
 *
 */
void pgaudit_initConfiguration(void) {
    /* init output configuration */
        /* current is nop */
    /* init options configuration */
        /* current is nop */
    auditRole = "";

    /* init rules configuration */
        /* current is nop */
}

/*
 * printConfigration()
 *
 * print configuration file.
 * Output destination, according to the setting of "logger parameters of output section".
 */
static void
printConfiguration(char *path) {
    struct stat file_stat;
    char header_string[1024];
    char* config_string;

    if (stat(path, &file_stat) == 0) {
        if ((config_string= getConfigurationString(path, file_stat.st_size)) != NULL) {
            /* header output */
            sprintf(header_string, "pgaudit: parsed configuration file(%s)", path);
            pgaudit_doOutput(header_string);

            /* configuration output */
            pgaudit_doOutput(config_string);
            pfree(config_string);
        }
    }
}

/*
 * getConfigurationString()
 *
 * It reads the contents of the configuration file into a string-buffer
 * (allocate buffer in this function).
 *
 */
static char*
getConfigurationString(char *path, int size) {
    char* buffer;
    FILE *fp;
    int i;
    char *content_header = "pgaudit: content\n";

    if ((fp = fopen(path, "r")) == NULL)
        return NULL;
    
    if ((buffer = palloc(size + strlen(content_header) + 2)) == NULL)
        return NULL;

    strcpy(buffer, content_header);
    i = strlen(content_header);
    while(!feof(fp)){
        fread(buffer + i,sizeof(char),1,fp);
        i++;
    }
    fclose(fp);

    /* Set null terminator */
    buffer[i] = '\0';
    
    return buffer;
}


/*
 * pgaudit_parseConfiguration
 *
 * To display the contents of the configuration file.
 * To parsing the configuration file.
 * If you fail parse the configuration file, set the default value.
 *
 * Return value
 *   parse succesed: 0
 *   parse failed: -1
 */
void pgaudit_parseConfiguration(char* filename) {
    FILE *fp;
    int ret = 0; /* parser retuen code */

    elog(DEBUG1, "pgaudit_parseConfiguration:filename=[%s]", filename);
    pgaudit_initConfiguration();

    if ( strlen(filename) == 0) {
        /* filename is empty, not continue */
        elog(DEBUG1, "pgaudit_parseConfiguration: filename empty");
        return;
    }

    if ((fp = fopen(filename, "r")) == NULL) {
        ereport(WARNING, 
            (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
             errmsg("pgaudit.config_file = %s    => file open error,"
                    " the default configuration is applied.", filename)));
        return;
    } else {
        /* parse by bison/flex */
        yyset_in(fp);
        if ((ret = yyparse()) != 0) {
            /* parse error */
            ereport(WARNING, 
                (errcode(ERRCODE_SUCCESSFUL_COMPLETION),
             	errmsg( "pgaudit.config_file = %s    => parse error,"
                        "All setting is reset in the default value.", filename)));
            pgaudit_initConfiguration();
            ret = -1;
        } else {
            /* print configuration */
            ereport(CONFNORMAL,
            	(errcode(ERRCODE_SUCCESSFUL_COMPLETION),
            	errmsg("pgaudit:  }")));
            printConfiguration(filename);
        }
        fclose(fp);


        elog(DEBUG1, "pgaudit_parseConfiguration:parse end, ret=%d", ret);
        return;
    }
}

#ifdef SET_CONFIG_UNIT_TEST
extern int yydebug;

int main(int argc, char** argv) {

    /* yydebug=1; */
    int ret;

    if(argc > 1) {
        ret = pgaudit_parseConfiguration(argv[1]);
        printf("ret=%d\n", ret);
    }
    return ret;
}
#endif
