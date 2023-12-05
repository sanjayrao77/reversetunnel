/*
 * misc.c - simple helper routines
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
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <pwd.h>
#define DEBUG
#include "common/conventions.h"

#include "misc.h"

int timeout_readn(int fd, unsigned char *msg, unsigned int len, time_t timeout) {
while (len) {
	int k;
	fd_set rset;
	struct timeval tv;

	FD_ZERO(&rset);
	FD_SET(fd,&rset);
	tv.tv_sec=1;
	tv.tv_usec=0;
	switch (select(fd+1,&rset,NULL,NULL,&tv)) {
		case -1:
			if (errno==EINTR) continue;
			return -1;
		case 0:
			if (time(NULL)>timeout) return -2;
			continue;
	}

	k=read(fd,(char *)msg,len);
	if (k<1) return -1;
#if 0
	fprintf(stderr,"%s:%d read %d bytes\n",__FILE__,__LINE__,k);
#endif
	len-=k;
	msg+=k;
}
return 0;
}
int timeout_writen(int fd, unsigned char *msg, unsigned int len, time_t timeout) {
fd_set wset;
FD_ZERO(&wset);
FD_SET(fd,&wset);
while (len) {
	int k;
	struct timeval tv;

	if (time(NULL)>timeout) {
		WHEREAMI;
		return -2;
	}
	tv.tv_sec=1;
	tv.tv_usec=0;
	switch (select(fd+1,NULL,&wset,NULL,&tv)) {
		case -1: 
			if (errno==EINTR) continue;
			WHEREAMI;
			return -1;
		case 0:
			FD_SET(fd,&wset);
			continue;
	}

	k=write(fd,(char *)msg,len);
	if (k<1) {
		WHEREAMI;
		return -1;
	}
#if 0
	fprintf(stderr,"%s:%d wrote %d bytes\n",__FILE__,__LINE__,k);
#endif
	len-=k;
	msg+=k;
}
return 0;
}

int getuid_misc(uid_t *uid_out, char *user) {
struct passwd *p;
if (!*user) { *uid_out=0; return 0; }
if (!(p=getpwnam(user))) GOTOERROR;
*uid_out=p->pw_uid;
return 0;
error:
	return -1;
}

unsigned int slowtou(char *str) {
unsigned int ret=0;
switch (*str) {
	case '1': ret=1; break;
	case '2': ret=2; break;
	case '3': ret=3; break;
	case '4': ret=4; break;
	case '5': ret=5; break;
	case '6': ret=6; break;
	case '7': ret=7; break;
	case '8': ret=8; break;
	case '9': ret=9; break;
	case '+':
	case '0': break;
	default: return 0; break;
}
while (1) {
	str++;
	switch (*str) {
		case '9': ret=ret*10+9; break;
		case '8': ret=ret*10+8; break;
		case '7': ret=ret*10+7; break;
		case '6': ret=ret*10+6; break;
		case '5': ret=ret*10+5; break;
		case '4': ret=ret*10+4; break;
		case '3': ret=ret*10+3; break;
		case '2': ret=ret*10+2; break;
		case '1': ret=ret*10+1; break;
		case '0': ret=ret*10; break;
		default: return ret; break;
	}
}
return ret;
}

static inline unsigned char _hexval(unsigned int a, unsigned int b) {
	/* a is high 4, b is low 4 */
if (a&64) a=((a&31)+9)<<4;
else a=(a&15)<<4;
if (b&64) b=(b&31)+9;
else b=b&15;
return (unsigned char)(a|b);
}

static unsigned char hexval(unsigned int a, unsigned int b) {
return _hexval(a,b);
}


void hexdecode(unsigned char *dest, unsigned int len, char *src) {
while (1) {
	*dest=hexval(src[0],src[1]);
	len--;
	if (!len) break;
	src+=2;
	dest+=1;
}
}

