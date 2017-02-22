[![Build Status](https://travis-ci.org/ossc-db/pgaudit.svg?branch=refactored)](https://travis-ci.org/ossc-db/pgaudit)

# pgaudit/pgaudit
## PostgreSQL Audit Extension
The PostgreSQL Audit extension (`pgaudit`) provides detailed session and/or object audit logging.

The goal of the PostgreSQL Audit extension (`pgaudit`) is to provide PostgreSQL users with capability to produce audit logs often required to comply with government, financial, or ISO certifications.

An audit is an official inspection of an individual's or organization's accounts, typically by an independent body. The information gathered by the PostgreSQL Audit extension (`pgaudit`) is properly called an audit trail or audit log. The term audit log is used in this documentation.

This is a forked `pgaudit` project based on original `pgaudit` project with changing design and adding some fatures.

## Why PostgreSQL Audit Extension?

Basic statement logging can be provided by the standard logging facility. This is acceptable for monitoring and other usages but does not provide the level of detail generally required for an audit. It is not enough to have a list of all the operations performed against the database. It must also be possible to find particular statements that are of interest to an auditor. The standard logging facility shows what the user requested, while `pgaudit` focuses on the details of what happened while the database was satisfying the request.

For example, an auditor may want to verify that a particular table was created inside a documented maintenance window. This might seem like a simple job for grep, but what if you are presented with something like this (intentionally obfuscated) example:

```
BEGIN
    EXECUTE 'CREATE TABLE import' || 'ant_table (id INT)';
END $$;
```

Standard logging will give you this:

```
LOG:  statement: DO $$
BEGIN
    EXECUTE 'CREATE TABLE import' || 'ant_table (id INT)';
END $$;
```

It appears that finding the table of interest may require some knowledge of the code in cases where tables are created dynamically. This is not ideal since it would be preferable to just search on the table name. This is where `pgaudit` comes in. For the same input, it will produce this output in the log:

```
AUDIT: SESSION,33,1,FUNCTION,DO,,,"DO $$
BEGIN
    EXECUTE 'CREATE TABLE import' || 'ant_table (id INT)';
END $$;"
AUDIT: SESSION,33,2,DDL,CREATE TABLE,TABLE,public.important_table,CREATE TABLE important_table (id INT)
```

Not only is the DO block logged, but substatement 2 contains the full text of the CREATE TABLE with the statement type, object type, and full-qualified name to make searches easy.
When logging SELECT and DML statements, `pgaudit` can be configured to log a separate entry for each relation referenced in a statement. For input "select * from team,member;" it will produce this output in the logs:

```
LOG:  AUDIT: OBJECT,34,1,READ,SELECT,TABLE,public.team,"select * from team,member;",<not logged>
LOG:  AUDIT: OBJECT,34,1,READ,SELECT,TABLE,public.member,"select * from team,member;",<not logged>
```

No parsing is required to find all statements that touch a particular table. In fact, the goal is that the statement text is provided primarily for deep forensics and should not be required for an audit.

## Usage Considerations
Depending on settings, it is possible for `pgaudit` to generate an enormous volume of logging. Be careful to determine exactly what needs to be audit logged in your environment to avoid logging too much.

For example, when working in an OLAP environment it would probably not be wise to audit log inserts into a large fact table. The size of the log file will likely be many times the actual data size of the inserts because the log file is expressed as text. Since logs are generally stored with the OS this may lead to disk space being exhausted very quickly. In cases where it is not possible to limit audit logging to certain tables, be sure to assess the performance impact while testing and allocate plenty of space on the log volume. This may also be true for OLTP environments. Even if the insert volume is not as high, the performance impact of audit logging may still noticeably affect latency.

To limit the number of relations audit logged for SELECT and DML statements, consider using `Object audit logging` (see [Object Audit Logging](#object_audit_logging)) and/or `Session audit logging` (see Session Audit Logging).
`Object audit logging` allows selection of the relations to be logged allowing for reduction of the overall log volume. However, when new relations are added they must be explicitly added to `Object audit logging`. A programmatic solution where specified tables are excluded from logging and all others are included may be a good option in this case.
`Session audit logging` allows selection of logs by rule with filters (see settings), to be logged allowing for reduction of the overall log volume.

## Session Audit Logging
`Session audit logging` provides detailed logs of all statements executed by a user in the backend, logs of postmaster (a start of database and Connection receive), and logs of these errors.

### Configuration

Log entries of `Session audit logging` are controlled via the `rule-section`. A `rule-section` setting defines a `format` and `filter`s. A `format` included in each rule section specifies a style of log entries like log_line_prefix. And each `filter` determines whether a log should be output or not according to its expressions. If you do not set any `rule-section`, `pgaudit` will output all logs that it can do.

The timing of `pgaudit` rule evaluation is when an execution of a simple SQL statement or a part of complex one is completed whether it successes or fails. So when a complex SQL like as 'COPY TO' is executed, log entry on the each part of the statement should be issued.

### Example

In this example `Session audit logging` is used for logging DDL and SELECT statements. Note that the insert statement is not logged since the WRITE class is not enabled

#### Inside of the file assigned by pgaudit.config_file:

```
[rule]
format = 'AUDIT: SESSION,%statement_id,%sub_statement_id,%class,%i,%object_type,%objrect_id,%command_text'
class = 'READ,WRITE'
object_name = 'account'
```

#### SQL:

```
CREATE TABLE account
(
    id int,
    name text,
    password text,
    description text
);
INSERT INTO account (id, name, password, description)
             VALUES (1, 'user1', 'HASH1', 'blah, blah');
SELECT * FROM account;
```

#### Log Output:

```
AUDIT: SESSION,1,1,DDL,CREATE TABLE,TABLE,public.account,CREATE TABLE account
(
    id int,
    name text,
    password text,
    description text
);
AUDIT: SESSION,2,1,READ,SELECT,TABLE, public.account,SELECT * FROM account
```

## Object Audit Logging {#object_audit_logging}

`Object audit logging` logs statements that affect a particular relation. Only SELECT, INSERT, UPDATE and DELETE commands are supported. TRUNCATE is not included in `Object audit logging`.

### Configuration
`Object audit logging` is implemented via the roles system. The option.role setting defines the role that will be used for audit logging. A relation (TABLE, VIEW, etc.) will be audit logged when the audit role has permissions for the command executed or inherits the permissions from another role. This allows you to effectively have multiple audit roles even though there is a single master role in any context.
Set option.role to auditor and grant SELECT and DELETE privileges on the account table. Any SELECT or DELETE statements on account will now be logged:
#### In the file named pgaudit.config_file

```
[option]
role = 'auditor'
```
#### SQL

```
GRANT SELECT, DELETE ON public.account To auditor;
```

### Example

In this example `Object audit logging` is used to illustrate how a granular approach may be taken towards logging of SELECT and DML statements. Note that logging on the account table is controlled by column-level permissions, while logging on account_role_map is table-level.

#### Inside of the file assigned by pgaudit.config_file:

```
[option]
role = 'auditor'
```

#### SQL:

```
CREATE TABLE account
(
    id int,
    name text,
    password text,
    description text
);
GRANT SELECT (password) ON public.account TO auditor;
SELECT id, name FROM account;
SELECT password FROM account;
GRANT UPDATE (name, password) ON public.account TO auditor;
UPDATE account SET description = 'yada, yada';
UPDATE account SET password = 'HASH2';
CREATE TABLE account_role_map
(
    account_id int,
    role_id int
);
GRANT SELECT ON public.account_role_map TO auditor;
SELECT account.password, account_role_map.role_id
  FROM account
       INNER JOIN account_role_map
            ON account.id = account_role_map.account_id
```

#### Log Output:

```
AUDIT: OBJECT,1,1,READ,SELECT,TABLE,public.account,SELECT password FROM account
AUDIT: OBJECT,2,1,WRITE,UPDATE,TABLE,public.account,UPDATE account
   SET password = 'HASH2'
AUDIT: OBJECT,3,1,READ,SELECT,TABLE,public.account,SELECT account.password,
       account_role_map.role_id
  FROM account
       INNER JOIN account_role_map
            ON account.id = account_role_map.account_id
AUDIT: OBJECT,3,1,READ,SELECT,TABLE,public.account_role_map,SELECT account.password,
       account_role_map.role_id
  FROM account
       INNER JOIN account_role_map
            ON account.id = account_role_map.account_id
```

### Format {#format}

Entries of `Object audit logging` are written to the destination that you set in the `output-section`. And these contain the following format (expression by format notation of the `rule-section`):

```
format='AUDIT:SESSION,%statement_id,%substatement_id,%class,%command_tag,%object_type,%object_name,%command_text,%command_paramator'
```

Use log_line_prefix to add any other fields that are needed to satisfy your audit log requirements. A typical log line prefix might be '%m %u %d: ' which would provide the date/time, user name, and database name for each audit log.

### Caveats

Object renames are logged under the name they were renamed to. For example, renaming a table will produce the following result:

```
ALTER TABLE test RENAME TO test2;
AUDIT: SESSION,36,1,DDL,ALTER TABLE,TABLE,public.test2,ALTER TABLE test RENAME TO test2
```

It is possible to have a command logged more than once. For example, when a table is created with a primary key specified at creation time the index for the primary key will be logged independently and another audit log will be made for the index under the create entry. The multiple entries will however be contained within one statement ID.

Autovacuum and Autoanalyze are not logged.

Statements that are executed after a transaction enters an aborted state will not be audit logged. However, the statement that caused the error and any subsequent statements executed in the aborted transaction will be logged as ERRORs by the SESSON-AUDIT-LOGGING.

## Compile and Install
Clone the PostgreSQL repository:

```
git clone https://github.com/postgres/postgres.git
```

Checkout REL9_5_STABLE branch:

```
git checkout REL9_5_STABLE
```

Make PostgreSQL:

```
./configure
make install -s
```

Change to the contrib directory:

```
cd contrib
```

Clone the `pgaudit` extension:

```
git clone https://github.com/pgaudit/pgaudit.git
```

Change to pgaudit directory:

```
cd pgaudit
```

Build pgaudit and run regression tests:

```
make -s check
```

Install pgaudit:

```
make install
```

## Database settings

### Configuration (postgresql.conf)

#### shared_preload_libraries

Set `pgaudit` program to shared_preload_libraries.

#### pgaudit.config_file

`pgaudit`.config_file assigns a file that includes the settings of `pgaudit`.

#### EVENT TRIGER
CREATE FUNCTION and CREATE EVENT TRIGER should be done for pgaudit_ddl_command_end() and pgaudit_ddl_command_end() at each database (or at template database) in order to log DDLs as follws:

```
CREATE FUNCTION pgaudit_ddl_command_end()
    RETURNS event_trigger LANGUAGE C AS 'pgaudit', 'pgaudit_ddl_command_end';
CREATE EVENT TRIGGER pgaudit_ddl_command_end
    ON ddl_command_end EXECUTE PROCEDURE pgaudit_ddl_command_end();
CREATE FUNCTION pgaudit_sql_drop()
    RETURNS event_trigger LANGUAGE C AS 'pgaudit', 'pgaudit_sql_drop';
CREATE EVENT TRIGGER pgaudit_sql_drop
    ON sql_drop EXECUTE PROCEDURE pgaudit_sql_drop();
```

The above procedures are done by CREATE EXTENSION but note that `CREATE EXTENSION pgaudit` must be called before any rule is specified.

#### ROLE

See [Object-Audit-Logging](#object_audit_logging).

## Setting Parameters via the file assigned by pgaudit.config_file

The settings are divided into sections where you can set some parameters to control `pgaudit`. They are "output", "option" and "rule" sections. "output" and "option" section cannot be defined more than once in configuration file while "rule" section can be define multiple times. All section names are case-insensitive. Every section includes one or more parameters. All parameter names are case-insensitive. Every parameter takes a value of one of three types: Boolean, String. Boolean values can be written as on, off, true, and false (all case-insensitive). String values can be written as comma-delimited strings between a couple of single quotes.

We will example of settings with descriptions of sections, below;

```
# Where to log (e.g. log to serverlog).
[output]
logger= 'serverlog'

# Behavior of the PGAUDIT (e.g. setting log_catalog)
[option]
log_catalog = true

# Selection conditions of the Session-Audit-Logging.
[rule]
format = 'CONNECTION: %d,%u,"%connection_message"'
class = 'CONNECT'

[rule]
format = 'DML: %d,%u,%class,%command_tag,"%object_name","%command_text"'
class = 'READ,WRITE'
```

##Comment (#Where to log)
A sharp ('#') and byte string after the sharp and before a return ('\n'), is recognized as a comment. And `pgaudit` ignores it.

##Output-section ([output])
Specifies where to logs. At most one `output-section` can be written at the beginning of the file. And if you use the default settings (output logs to the 'serverlog' with the level 'LOG'), `output-section` is not necessary.
The `output-section` begins with the word "[output]". We will show two examples with descriptions of key words and values below;

```
# Example 1: set all possible parameters to use serverlog.
[output]
logger	= 'serverlog'
level	= 'LOG'
```

```
# Example 2: set all possible parameters to use syslog.
[output]
logger	= 'syslog'
pathlog = '/home/auditor/syslog'
facility = 'LOG_USER'
priority = 'LOG_WARNING'
ident	= 'PGAUDIT'
option	= 'LOG_CONS|LOG_PERROR|LOG_PID'
```

#### Logger (logger = 'serverlog', logger= 'syslog')

Set the logger that you use. The values can be 'serverlog' (PostgreSQL logger) or 'syslog'.

The default is 'serverlog'.

#### Level (level = 'LOG')

Parameter for servrlog. Specifies the log level that will be used for log entries (see Message Severity Levels for valid levels but note that ERROR, FATAL, and PANIC are not allowed). This setting is used for regression testing and may also be useful to end users for testing or other purposes.

The default setting is 'LOG'.

#### Pathlog (pathlog = '/home/auditor/syslog')

Parameter for syslog. Specifies the socket to which syslogd listens (See $SystemLogSocketName, in case of rsyslog).

The default setting is '/dev/log'.

#### Facility, Priority, Ident and Option

Parameters for syslog, see 'man 3 syslog' for values.

The default setting is 'LOG_USER', 'LOG_WARNING','PGAUDIT', and 'LOG_CONS|LOG_PID'.

#### Note:

When the same keyword is set more than once in a section, the last setting is effective.

### Option-section ([option])

Specifies the behavior of the `pgaudit`. At most one `option-section` can be written at the top of the file or at just after `output-section`. And if you use the default settings, the `option-section` is not necessary.

The `option-section` begins with the word `[option]`. We will show an examples, and descriptions of key word and values below;

```
# Example : set all possible parameters.
[option]
log_catalog = true
log_parameter = off
log_statement_once = OFF
role = 'auditor'
```

#### log_catalog (log_catalog = on)

Specifies that session logging should be enabled in the case where all relations in a statement are in pg_catalog. Disabling this setting will reduce noise in the log from tools like psql and PgAdmin that query the catalog heavily.

The default is on.

#### log_parameter (log_parameter = off)

Specifies that audit logging should include the parameters that were passed with the statement. When parameters are present they will be included in CSV format after the statement text.

The default is off.

#### log_statement_once (log_statement_once = off)

Specifies whether logging will include the statement text and parameters with the first log entry for a statement/substatement combination or with every entry. Disabling this setting will result in less verbose logging but may make it more difficult to determine the statement that generated a log entry, though the statement/substatement pair along with the process id should suffice to identify the statement text logged with a previous entry.

The default is off.

#### role (role = 'auditor')

Specifies the master role to use for `Object audit logging`. Multiple audit roles can be defined by granting them to the master role. This allows multiple groups to be in charge of different aspects of audit logging.

The default is NULL.

### Rule-section ([rule])

Specifies the conditions for selecting log entries based on the rules included. For a given log, `pgaudit` evaluates each filter's conditions in a rule and outputs a log entry if all the filter conditions are satisfied.
When there are several rules in the section, `pgaudit` test all of them and emits log entries as far as they are satisfied. When putting out a log entry, `pgaudit` formats it along with `format` filter, which is always satisfied.
`rule-section` themselves can be specified more than once in the settings file.

We will show two examples with usage notes on key words and values below;

```
# Example1 : log nothing
[rule]
format= ''
class = 'NONE'
```

```
# example2:
# rule 1 : no filter. log all logs
[rule] #1
format = 'ALL: %t,%d,%u,%class,%cmmand_tag,"%object_name","%command_text"'

#rule 2; log DML in AM
[rule] #2.
format = 'DML-AM: %d,%u,%class,%command_tag,"%object_name","%command_text"'
class = 'READ,WRITE'
timestamp = '00:00:00-11:59:59'

#rule 3 ; log DML in PM
[rule] #3
format    =  'DML-PM: %d,%u,%class,%command_tag,"%object_name","%command_text"'
class      = ' READ , WRITE '
timestamp != '00:00:00-05:59:59, 06:00:00-11:59:59'

# on these rules (#1,#2,#3), `pgaudit` outputs two lines( #1and#2 or #1and#3) for a DML.
```

#### Format (format = '...')

The `format` is used for log entry formatting. It is syntactically a kind of rule filter and begins with keyword (`format`) followed by an operator ('='), and a format-string (in a literal).

One `format` should be written at the top of each `rule-section`.

The syntax of format-string is similar to that of log_line_prefix of PostgreSQL. Each character in the format-string is output in the log entry except escape sequences, which begin with percent Chariot (%) followed by the particular strings, which are shown below. Each escape sequence is substituted with its value when it is evaluated. The other strings begin with % are not recognized as escape sequences and are output as they are.

The Escapes.

- %application_name or %a

 Similar to %a of log_line_prefix.

- %class

 classes of statements. Values are:
 -	READ: SELECT and COPY FROM.
 -	WRITE: INSERT, UPDATE, DELETE, TRUNCATE, and COPY TO.
 -	FUNCTION: Function calls and DO blocks.
 -	ROLE: Statements related to roles and privileges: GRANT, REVOKE, CREATE/ALTER/DROP ROLE.
 -	DDL: All DDL that is not included in the ROLE class.
 -	CONNECT : Connection events. request, authorized, and disconnect.
 -	SYSTEM : Server start up. ready, normal and interrupted.
 -	BACKUP : pg_basebackup.
 -	ERROR : Event that ended by an error (PostgreSQL Error Code is not in the Class 00 ). Available when log_min_message is set to ERROR or lower.
 -	MISC: Miscellaneous commands, e.g. DISCARD, FETCH, CHECKPOINT, VACUUM.

- %command_tag	or %i

 e.g. ALTER TABLE, SELECT.

 Available for SELECT, DML and most DDL statements.

- %command_text

 Statement executed on the backend.

 Available for SELECT, DML and most DDL statements.

- %command_parameter

 If `pgaudit`.log_parameter is set then this field will contain the statement parameters as blank delimited values. 

 Available for SELECT, DML and most DDL statements.

- %connection_message

 Message for Connection Class. Values are:

 - received (connection received),
 - authorized (connection received),
 - disconnected (connection disconnected),
 - ready (database system is ready to accept connections),
 - normal ended (last time, database system was normal ended),
 - interrupted (last time, database system was ended by interrupts).

- %current_user

 Current user id.

- %database or %d

 similar to %d of log_line_prefix.

- %object_name

 The fully-qualified object name (e.g. public.account).

 Available for SELECT, DML and most DDL statements.

- %object_type

 The type of objects like as TABLE, INDEX, VIEW, MATERIALIZED_VIEW, SEQUENCE, COMPOSITE_TYPE, FOREIGN_TABLE, FUNCTION, TOAST_VALUE, UNKNOWN.

 Available for SELECT, DML and most DDL statements

- %pid or %p

 similar to %p of log_line_prefix.

- %remote_host or %h

 similar to %h of log_line_prefix.

- %remote_port

 Client port number of the connection.

- %statement_id

 Unique statement ID for this session. Each statement ID represents a backend call. Statement IDs are sequential even if some statements are not logged. There may be multiple entries for a statement ID when more than one relation is logged.

- %sub_statement_id

 Sequential ID for each substatement within the main statement. For example, calling a function from a query. Substatement IDs are continuous even if some substatements are not logged. There may be multiple entries for a substatement ID when more than one relation is logged.

- %timestamp or %t

 similar to %t of log_line_prefix.

- %user or %u

 similar to %u of log_line_prefix.

- %virtual_xid or %v

 similar to %v of log_line_prefix.

- %%

 similar to %% of log_line_prefix.

- The default is:

```
'AUDIT: SESSION,%statement_id,%sub_statement_id,%class,%command_tag,%object_type,%object_name,%command_text'
```

- Note: When you write returns ('\n') in a format, returns ('\n') will also be reflected in logs.

### Filter (... = '...' or ... != '...'):

Specifies how to narrow down the logs. (If there are no filters in a `rule-section`, `pgaudit` outputs as many logs as it can.) A filter is defined by a set of expression, which begins with a keyword (as it is shown below) followed by a comparison operator ('=': is in / '!=': is not in), and the set of the values.

#### Evaluation rule

When a log event arrives, all expression is evaluated at once. If all expressions in a `rule-section` are evaluated true, log entry is output. In an expression, its comparison operator '=' is evaluated true when the value derived from the keyword of the right-hand side is found in the value list of the left-hand side. The operator '!=' is evaluated true when the value of the right-hand side not matched any element of the list in the left-hand side.

The following keywords (a part of escapes written to the format) can be used:

```
class
command_tag
audit_role
database
object_type
object_name
remote_host
remote_port
timestamp
```

- timestamp (timestamp = '00:00:00--11:59:59')

Specifies the filter by timestamps. When this keyword is used in an expression, possible values in the left-hand side are an interval and comma delimited intervals, which is a pair of timestamps (start and end). The format for timestamp pair is fixed as 'hh:mm:dd-hh:mm:dd';
 hh,mm and dd, are 2 digits, hh is 24-hour representation. And in an interval, the start timestamp should be smaller (earlier) than the end timestamp.

The end of an interval is prolonged to just before the next second of later timestamp. For example, '11:00:00-11:59:59' means an interval, 'starts at just 11:00:00' and 'ends at just before 12:00:00 (=11:59.59 999msec).
The timestamp used `pgaudit` rule evaluation internally is different from one issued in the log entry. Because when `pgaudit` output a log entry after evaluation, it generates timestamp for log entry.

- class

Specifies which classes of statements will be logged. Possible values are a comma-delimited list of the values, and the values we described for `%class` (see [Format](#format)).

- object_type

Specifies which type of objects will be logged. Possible values are a comma-delimited list of the values which was described for `%object_type` (see [Format](#format)).

- audit_role

Specifies which use belonging  to role will be logged.  Possible values are a comma-delimited list of the values.

- command_tag, database, object_name, remote_host, remote_port

Specifies which database elements in the statements will be logged. Possible values are a comma-delimited list. Spaces and tabs between the values and commas are ignored. In the value '%' can be used for backward match or forward match.

## Note

- To use the syslogd

 To use the syslogd (in case of rsyslog) for `pgaudit`, consider the parameter following:

 - $MaxMessageSize

     This should be set to a value greater than the length of the longest audit log message. Otherwise, the rear of the log message may be lost.

 - $SystemLogSocketName

     Value to be set in the pathlog of `output-section`.

 - $EscapeControlCharactersOnReceive

 This should be set to off. Otherwise, control characters in the log message will be converted to escapes. (E.g. #011('\t'), #012('\n'))

- Logs of error

 `Session audit logging` logs a log for a SQL (Success or Error) for simple SQL, but sometimes, especially for complex SQL, logs some of logs (for each parts and an Error).

- pgaudit must be set log\_connections, log\_disconnections and log\_replication\_commands is on. If all these parameters are not on, the PostgreSQL server will not start.

## Authors

The PostgreSQL Audit Extension is based on the pgaudit project at https://github.com/pgaudit/pgaudit.
