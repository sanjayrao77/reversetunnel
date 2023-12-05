/*
 * log.c - wrapper for syslog and fprintf
 * Copyright (C) 2023 Sanjay Rao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#define DEBUG
#include "common/conventions.h"

#include "log.h"

CLEARFUNC(log);

int reinit_log(struct log *log, FILE *fout, int issyslog, unsigned int levels) {
// set levels to ALL_LOG for all messages, NORMAL_LOG for normal
if (issyslog && !log->issyslog) {
	(void)openlog(NULL,LOG_PID,LOG_DAEMON);
}
log->fout=fout;
log->issyslog=issyslog;
log->level_bitmask=levels;
return 0;
}

void deinit_log(struct log *log) {
if (log->issyslog) {
	(void)closelog();
}
if (log->tofree.f) fclose(log->tofree.f);
}

int message_log(struct log *log, unsigned int level, const char *fmt, ...) {
if (!(level&log->level_bitmask)) return 0;
if (log->fout) {
	va_list args;
	va_start(args,fmt);
	(ignore)vfprintf(log->fout,fmt,args);
	va_end(args);
}
if (log->issyslog) {
	va_list args;
	int priority=LOG_DAEMON;
	va_start(args,fmt);
	if (level>1) priority|=LOG_DEBUG;
	else priority|=LOG_INFO;
	(void)vsyslog(priority,fmt,args);
	va_end(args);
}
return 0;
}
