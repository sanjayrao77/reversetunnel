/*
 * dynamic.c - program to run satellite side of reversetunnel
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
#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <errno.h>
#include <sys/wait.h>
#define DEBUG
#include "common/conventions.h"
#include "tls.h"
#include "misc.h"
#include "log.h"
#include "connector.h"

#define IPV4(a,b,c,d) ((a)|((b)<<8)|((c)<<16)|((d)<<24))
// ports below 1000 are less likely to be hijacked but the server might not allow it
#define ROOT_TUNNEL_PORT	632
// if the server is non-root, it will try port 6321 instead of 632
// switching ports requires a recompile; we don't want to make it too easy since it could be insecure
#define NOTROOT_TUNNEL_PORT	6321

// default to local sshd
#define SERVER_PORT 22
#define SERVER_IP4	IPV4(127,0,0,1)
#define ALARM_SECONDS	(60*60*1)

int main(int argc, char **argv) {
struct connector connector;
struct log log;
uint32_t ipv4_tunnel=0;
uint32_t ipv4_server=SERVER_IP4;
unsigned short port_tunnel=ROOT_TUNNEL_PORT,port_server=SERVER_PORT;
unsigned char hostname8[8+1]={'n','o','n','e',0,0,0,0,0};
unsigned char password8[8]={'P','a','S','s','W','o','R','d'};
pid_t pid;
int isverbose=0;
int ishostname=0;
int isfork=1;
int isnobody=1;
int alarm_seconds=ALARM_SECONDS;

clear_connector(&connector);
clear_log(&log);

{
	int i;
	for (i=1;i<argc;i++) {
		struct in_addr inaddr;
		char *arg=argv[i];
		if (!strncmp(arg,"--hostname=",11)) {
			strncpy((char *)hostname8,arg+11,8);
			ishostname=1;
		} else if (!strncmp(arg,"--password=",11)) {
			char *pwd;
			pwd=arg+11;
			if (strlen(pwd)!=16) {
				fprintf(stderr,"%s:%d password should be 16 characters, hex encoded\n",__FILE__,__LINE__);
				GOTOERROR;
			}
			(void)hexdecode(password8,8,pwd);
		} else if (!strncmp(arg,"--localport=",12)) {
			port_server=(unsigned short)slowtou(arg+12);
		} else if (!strncmp(arg,"--localip=",10)) {
			if (!inet_aton(arg+10,&inaddr)) GOTOERROR;
			ipv4_server=inaddr.s_addr;
		} else if (!strncmp(arg,"--remoteip=",11)) {
			if (!inet_aton(arg+11,&inaddr)) GOTOERROR;
			ipv4_tunnel=inaddr.s_addr;
		} else if (!strncmp(arg,"--remoteport=",13)) {
			port_tunnel=(unsigned short)slowtou(arg+13);
		} else if (!strncmp(arg,"--alarm=",8)) {
			alarm_seconds=(unsigned short)slowtou(arg+8);
		} else if (!strcmp(arg,"--verbose")) {
			isverbose=1;
		} else if (!strcmp(arg,"--notroot")) {
			isnobody=0;
		} else if (!strcmp(arg,"--debug")) {
			isfork=0;
			isverbose=1;
		} else if (!strcmp(arg,"--help")) {
			fprintf(stdout,"reversetunnel, remote component\n");
			fprintf(stdout,"--localip=IP : IP of local service, default is 127.0.0.1\n");
			fprintf(stdout,"--localport=PORT : port number of local service, default is 22(sshd)\n");
			fprintf(stdout,"--remoteip=IP : IP of fixed component, required\n");
			fprintf(stdout,"--remoteport=PORT : PORT of fixed component, default is 632\n");
			fprintf(stdout,"--alarm=SECONDS : kill process after SECONDS, 0 to disable, default is 3600\n");
			fprintf(stdout,"--verbose: print more status messages\n");
			fprintf(stdout,"--notroot: run as a user (don't setuid to nobody)\n");
			fprintf(stdout,"--debug: run in foreground\n");
			return 0;
		} else {
			fprintf(stderr,"%s:%d unknown argument %s\n",__FILE__,__LINE__,arg);
			GOTOERROR;
		}
	}
}
if (!ipv4_tunnel) {
	fprintf(stderr,"%s:%d remote ip is required\n",__FILE__,__LINE__);
	GOTOERROR;
}
if (!ishostname) {
	(ignore)gethostname((char *)hostname8,9);
}

if (isnobody) {
	uid_t nobody;
	if (getuid_misc(&nobody,"nobody")) GOTOERROR;
	if (setuid(nobody)) GOTOERROR;
}

unsigned int loglevels=NORMAL_LOG;
if (isverbose) loglevels=ALL_LOG;

if (isfork) {
	pid=fork();
	if (pid<0) GOTOERROR;
	if (pid) _exit(0);
	if (init_log(&log,NULL,1,loglevels)) GOTOERROR;
} else {
	if (init_log(&log,stderr,0,loglevels)) GOTOERROR;
}

while (1) {
	pid=fork();
	if (!pid) break;
	if (pid<0) {
		sleep(60);
		continue;
	}
	while (1) {
		pid_t r;
		r=waitpid(-1,NULL,0);
		if (r<0) {
			if (errno==EINTR) continue;
			GOTOERROR;
		}
		if (r==pid) break;
	}
	sleep(10);
}

if (alarm_seconds) alarm(alarm_seconds);

if (init_connector(&connector,&log,ipv4_tunnel,port_tunnel,ipv4_server,port_server,
		(unsigned char *)"PaSsWoRd",hostname8)) GOTOERROR;

{
	(ignore)message_log(&log,VERBOSE_LOG,"%s:%d connecting to tunnel\n",__FILE__,__LINE__);
	if (connecttunnel_connector(&connector)) GOTOERROR;
	(ignore)message_log(&log,VERBOSE_LOG,"%s:%d waiting for client\n",__FILE__,__LINE__);
	if (waitforclient_connector(&connector)) GOTOERROR;
	(ignore)message_log(&log,VERBOSE_LOG,"%s:%d connecting to server\n",__FILE__,__LINE__);
	if (connectserver_connector(&connector)) GOTOERROR;
	(ignore)message_log(&log,VERBOSE_LOG,"%s:%d proxying data\n",__FILE__,__LINE__);
	if (proxyclients_connector(&connector)) GOTOERROR;
	(void)reset_connector(&connector);
}

deinit_connector(&connector);
return 0;
error:
	deinit_connector(&connector);
	return -1;
}
