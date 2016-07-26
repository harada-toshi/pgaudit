/*
 * pgaudit_syslog.c
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * Customized syslog.c for pgaudit.
 *
 * ORIGINAL:
 * 	Copyright of syslog.c is as follws:
 *
 * -------------------------------------------------------------------------- 
 * Copyright (nclude <unistd.h>c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * -------------------------------------------------------------------------- 
 *
 * POINTS OF CUSTOMIZE:
 * 1. Rewrite and rename
 * 2. Add socketpath parametor into open function. The default is /dev/log.
 * 3. Delete SIGPIPE handling with lock functions.
 * 4. Addresses some issues with fallows;
 *  a. Possibility that the multibyte character gets mixed in a date form.
 *  b. Possibility that the size is short when reconnecting by TCP or UDP.
 *	c. The message level, after open_memstream() returns NULL.
 *
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit_syslog.c
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <paths.h>
#include <fcntl.h>
#include "pgaudit_syslog.h"

static void pgaudit_syslog_internal(int pri,const char *fmt,va_list ap);

static int LogType = SOCK_DGRAM;        /* type of socket connection */
static int LogFile = -1;                /* fd for log */
static int connected = 0;               /* have done connect */
static int LogStat = 0;                 /* status bits, set by pgaudit_openlog() */
static const char *LogTag = NULL;       /* string to tag the entry with */
static const char *LogSocket = NULL;    /* socket name, set by pgaudit_openlog() */
static int LogFacility = LOG_USER;      /* default facility code */
static int LogMask = 0xff;	        /* mask of priorities to be logged */	
extern char *__progname;                /* Program name, from crt0. */

static struct sockaddr_un SyslogAddr;   /* AF_UNIX address of local logger */

#define INTERNALLOG_OPTION   LOG_ERR|LOG_CONS|LOG_PERROR|LOG_PID
#define INTERNALLOG_SOCKET   "/dev/log"

void pgaudit_openlog(const char *ident, int logstat, int logfac,const char *socketpath)
{
	int retry = 0;
	
	if (ident != NULL)
		LogTag = ident;
	LogStat = logstat;
	if (logfac != 0 && (logfac &~ LOG_FACMASK) == 0)
		LogFacility = logfac;
	if (socketpath != NULL)
		LogSocket = socketpath;

	while (retry < 2) {
		if (LogFile == -1)
		{
			SyslogAddr.sun_family = AF_UNIX;

			if (LogSocket != NULL)
				strncpy(SyslogAddr.sun_path,LogSocket,sizeof(SyslogAddr.sun_path));
			else
				strncpy(SyslogAddr.sun_path,INTERNALLOG_SOCKET,sizeof(SyslogAddr.sun_path));

			if (LogStat & LOG_NDELAY) {
				LogFile = socket(AF_UNIX,LogType,0);
				if (LogFile == -1)
					return;
			}
		}
		if (LogFile != -1 && !connected)
		{
			int old_errno = errno;
			if( connect(LogFile,(struct sockaddr *)&SyslogAddr,sizeof(SyslogAddr))
				== -1)
			{
				int saved_errno = errno;
				int fd = LogFile;
				LogFile = -1;
				close(fd);
				errno = old_errno;
				if (saved_errno == EPROTOTYPE)
				{
					LogType = (LogType == SOCK_DGRAM ? SOCK_STREAM : SOCK_DGRAM);
					++retry;
					continue;
				}
			}
			else
				connected = 1;
		}
		break;
	}
	
	return;
}

void pgaudit_syslog(int pri,const char *format,...)
{
	va_list arg;
	va_start(arg, format);
	pgaudit_syslog_internal(pri,format,arg);
	va_end(arg);

	return;
}

static void pgaudit_syslog_internal(int pri,const char *fmt,va_list ap)
{
	FILE *f;
	char *buf = 0;
	size_t bufsize = 0;

	time_t now;
	int fd;
	int save_errno;
	size_t msgoff;
	char strtmp[16];
	char ctime_buf[26];
	char failbuf[64];

	save_errno = errno;

	/* Check for invalid bits. */
	if (pri & ~(LOG_PRIMASK|LOG_FACMASK))
	{
		pgaudit_syslog(INTERNALLOG_OPTION,"pgaudit_syslog: unknown facility/priority: %x",pri);
		pri &= LOG_PRIMASK|LOG_FACMASK;
	}

	/* Check pri against setlogmask values. */
	if ((LOG_MASK (LOG_PRI (pri)) & LogMask) == 0)
		return;

	/* Set default logfac if none specified. */
	if ((pri & LOG_FACMASK) == 0)
		pri |= LogFacility;
	
	/* timestamp */
	memset(strtmp,0x00,sizeof(strtmp));
	memset(ctime_buf,0x00,sizeof(ctime_buf));
	time(&now);
	ctime_r(&now,ctime_buf);
	strncpy(strtmp,&(ctime_buf[4]),15);
	strtmp[15] = '\0';

	errno = save_errno;

	/* Build the message in a memory-buffer stream.  */
	f = open_memstream (&buf, &bufsize);
	if (f == NULL)
	{
		/* We cannot get a stream.  There is not much we can do but
		 *    emitting an error messages.  */
		memset(failbuf,0x00,sizeof(failbuf));
		buf = failbuf;
		msgoff = snprintf(failbuf,sizeof(failbuf)-1,"<%d>%s",pri,strtmp);
		bufsize = msgoff;
		bufsize += snprintf(failbuf+msgoff,sizeof(failbuf)-msgoff-1," out of memory [%d]",getpid());
	}
	else
	{
		fprintf(f, "<%d>%s ", pri,strtmp);
		msgoff = ftell(f);

		if(LogTag == NULL)
			LogTag = __progname;
		if(LogTag != NULL)
			fputs(LogTag, f);
		if(LogStat & LOG_PID)
			fprintf (f, "[%d]", (int)getpid());
		if(LogTag != NULL)
			fputs(": ", f);
		
		vfprintf (f, fmt, ap);

		/* Close the memory stream; this will finalize the data
 		   into a malloc'd buffer in BUF.  */
		fclose(f);
	}

	/* Output to stderr if requested. */
	if (LogStat & LOG_PERROR)
	{
		struct iovec iov[2];
		register struct iovec *v = iov;

		v->iov_base = buf + msgoff;
		v->iov_len = bufsize - msgoff;

		/* Append a newline if necessary.  */
		if (buf[bufsize - 1] != '\n')
		{
			++v;
			v->iov_base = (char *) "\n";
			v->iov_len = 1;
		}
		writev(STDERR_FILENO, iov, v - iov + 1);
	}

	/* Get connected, output the message to the local logger. */
	if(!connected)
		pgaudit_openlog(LogTag, LogStat|LOG_NDELAY,0,NULL);

	/* If we have a SOCK_STREAM connection, also send ASCII NUL as
  	   a record terminator.  */
	if (LogType == SOCK_STREAM)
		bufsize++;	

	/* Try to send */
	if(!connected || send(LogFile, buf, bufsize, 0) < 0)
	{
		/* Reconnect if connected (error on send). */
		if(connected)
		{
			/* Try to reopen the syslog connection.  Maybe it went down.  */
			pgaudit_closelog();
			if(LogType == SOCK_STREAM)
				bufsize--;

			pgaudit_openlog(LogTag, LogStat|LOG_NDELAY,0,NULL);
			if(LogType == SOCK_STREAM)
				bufsize++;
		}

		/* Retry to send */
		if (!connected || send(LogFile, buf, bufsize, 0) < 0)
		{
			pgaudit_closelog(); /* attempt re-open next time */
			/*
			 * Output the message to the console; don't worry
			 * about blocking, if console blocks everything will.
			 * Make sure the error reported is the one from the
			 * syslogd failure.
			 */
			if (LogStat & LOG_CONS &&
			  (fd = open(_PATH_CONSOLE, O_WRONLY|O_NOCTTY, 0)) >= 0)
			{
				dprintf(fd,"%s\r\n", buf+msgoff);
				close(fd);
			}
		}
	}

	if (buf != failbuf)
		free(buf);

	return;
}

void pgaudit_closelog(void)
{
	if(!connected)
		return;

	close(LogFile);
	LogFile = -1;
	connected = 0;

	return;
}

int pgaudit_setlogmask(int pmask)
{
	int omask = LogMask;

	if(pmask != 0)
		LogMask = pmask;

	return(omask);
}
