/*
 * fixed.c - program to run the static ip side of reversetunnel 
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
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#define DEBUG
#include "common/conventions.h"
#include "common/blockmem.h"
#include "misc.h"
#include "tls.h"
#include "log.h"
#include "control.h"
#include "supervisor.h"
#include "listener.h"

#define IPV4(a,b,c,d) ((a)|((b)<<8)|((c)<<16)|((d)<<24))

#define MAX_TUNNELS	5

// #define LOCALIP IPV4(192,168,1,8)

static void chld_signal_handler(int sig, siginfo_t *info, void *ucontext) {
}


static int mainloop(struct log *log, unsigned char *password8, char *keyfile, char *certfile,
		unsigned int maxtunnels, uint32_t tunneladdr, unsigned short tunnelport,
		uint32_t clientaddr, char *cpath, int isnobody) {
struct sigaction sachld={.sa_sigaction=chld_signal_handler};
struct supervisor supervisor;

clear_supervisor(&supervisor);

if (sigaction(SIGCHLD,&sachld,NULL)) GOTOERROR;
if (init_supervisor(&supervisor,log,maxtunnels,tunneladdr,tunnelport,clientaddr,password8,keyfile,certfile)) GOTOERROR;
(ignore)message_log(log,VERBOSE_LOG,"%s:%d waiting on port %u\n",__FILE__,__LINE__,tunnelport);
if (cpath) {
	if (addcontrol_supervisor(&supervisor,cpath)) GOTOERROR;
}
#if 0
if (add_tunnel_authorized_supervisor(&supervisor,IPV4(127,0,0,1))) GOTOERROR;
if (add_client_authorized_supervisor(&supervisor,IPV4(127,0,0,1))) GOTOERROR;
if (add_client_authorized_supervisor(&supervisor,IPV4(192,168,1,8))) GOTOERROR;
#endif

if (isnobody) {
	uid_t nobody;
	if (getuid_misc(&nobody,"nobody")) GOTOERROR;
	if (setuid(nobody)) GOTOERROR;
}

while (1) {
	if (step_supervisor(&supervisor)) GOTOERROR;
	if (supervisor.isquit) break;
}

deinit_supervisor(&supervisor);
return 0;
error:
	deinit_supervisor(&supervisor);
	return -1;
}

static int connecttounix(char *path) {
struct sockaddr_un su;
int fd=-1;
int namelen;

memset(&su,0,sizeof(struct sockaddr_un));
su.sun_family=PF_UNIX;
namelen=strlen(path)+1;
if (namelen>sizeof(su.sun_path)) GOTOERROR;
memcpy(su.sun_path,path,namelen);
fd=socket(AF_UNIX,SOCK_STREAM,0);
if (fd<0) GOTOERROR;
if (connect(fd,(struct sockaddr*)&su,sizeof(struct sockaddr_un))) GOTOERROR;
return fd;
error:
	ifclose(fd);
	return -1;
}

static int handlecontrolcommand(struct log *log, char *cpath, int type, uint32_t ipv4_arg) {
int fd=-1;
struct cmd_control cmd;

if (0>(fd=connecttounix(cpath))) GOTOERROR;

cmd.type=type;
if (ipv4_arg) cmd.oneip.ipv4=ipv4_arg;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;
while (1) {
	if (timeout_readn(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;
	switch (cmd.type) {
		case ONEIP_TYPE_CMD_CONTROL:
			fprintf(stdout,"IP: %u.%u.%u.%u\n", cmd.oneip.ipv4&0xff, (cmd.oneip.ipv4>>8)&0xff,
					(cmd.oneip.ipv4>>16)&0xff, (cmd.oneip.ipv4>>24)&0xff);
			break;
		case ONETUNNEL_TYPE_CMD_CONTROL:
			{
				char hostname[9];
				time_t timestamp;
				memcpy(hostname,cmd.onetunnel.hostname8,8);
				hostname[8]=0;
				timestamp=(time_t)cmd.onetunnel.timestamp;
				fprintf(stdout,"Tunnel: pid:%d port:%u remoteip:%u.%u.%u.%u hostname:%s timestamp:%s",
						cmd.onetunnel.pid, cmd.onetunnel.port,
						cmd.onetunnel.ipv4&0xff, (cmd.onetunnel.ipv4>>8)&0xff,
						(cmd.onetunnel.ipv4>>16)&0xff, (cmd.onetunnel.ipv4>>24)&0xff,
						hostname,ctime(&timestamp));
			}
			break;
		case TERMINATOR_TYPE_CMD_CONTROL: goto doublebreak;
	}
}
doublebreak:

return 0;
error:
	return -1;
}

int main(int argc, char **argv) {
struct log log;
#define ROOT_TUNNELPORT	632
#define NOTROOT_TUNNELPORT	6321
unsigned short tunnelport=0;
#define ROOT_CPATH "/var/run/rtunnel.socket"
#define NOTROOT_CPATH "/tmp/rtunnel.socket"
char *cpath=NULL;
char *keyfile="certs/fixed.key";
char *certfile="certs/fixed.cert";
unsigned char password8[8]={'P','a','S','s','W','o','R','d'};
uint32_t clientaddr=0;
uint32_t ipv4_arg=0;
unsigned int maxtunnels=MAX_TUNNELS;
int isnobody=1;
int isverbose=0;
int isfork=1;
int isnotroot=0;
int isserver=1;
unsigned int loglevels=NORMAL_LOG;

clear_log(&log);

{
	int i;
	for (i=1;i<argc;i++) {
		char *arg=argv[i];
		if (!strcmp(arg,"--verbose")) {
			isverbose=1;
		} else if (!strcmp(arg,"--debug")) {
			isfork=0;
			isverbose=1;
		} else if (!strcmp(arg,"--notroot")) {
			isnotroot=1;
			isnobody=0;
		} else if (!strncmp(arg,"--socketname=",13)) {
			cpath=arg+13;
		}
	}
}

if (!cpath) {
	cpath=isnotroot?NOTROOT_CPATH:ROOT_CPATH;
}

if (isverbose) loglevels=ALL_LOG;

{
	int i;
	for (i=1;i<argc;i++) {
		struct in_addr inaddr;
		char *arg=argv[i];
		int cmd_arg=0;

		if (!strcmp(arg,"--list-tunnels")) {
			cmd_arg=LIST_TUNNELS_TYPE_CMD_CONTROL;
		} else if (!strcmp(arg,"--list-allowed-tunnels")) {
			cmd_arg=LIST_AUTHORIZED_TUNNEL_TYPE_CMD_CONTROL;
		} else if (!strcmp(arg,"--list-allowed-clients")) {
			cmd_arg=LIST_AUTHORIZED_CLIENT_TYPE_CMD_CONTROL;
		} else if (!strcmp(arg,"--lastip-client")) {
			cmd_arg=LASTIP_CLIENT_TYPE_CMD_CONTROL;
		} else if (!strcmp(arg,"--lastip-tunnel")) {
			cmd_arg=LASTIP_TUNNEL_TYPE_CMD_CONTROL;
		} else if (!strncmp(arg,"--addip-tunnel=",15)) {
			cmd_arg=ADDIP_TUNNEL_TYPE_CMD_CONTROL;
			if (!inet_aton(arg+15,&inaddr)) GOTOERROR;
			ipv4_arg=inaddr.s_addr;
		} else if (!strncmp(arg,"--addip-client=",15)) {
			cmd_arg=ADDIP_CLIENT_TYPE_CMD_CONTROL;
			if (!inet_aton(arg+15,&inaddr)) GOTOERROR;
			ipv4_arg=inaddr.s_addr;
		} else if (!strncmp(arg,"--password=",11)) {
			char *pwd;
			pwd=arg+11;
			if (strlen(pwd)!=16) {
				fprintf(stderr,"%s:%d password should be 16 characters, hex encoded\n",__FILE__,__LINE__);
				GOTOERROR;
			}
			(void)hexdecode(password8,8,pwd);
		} else if (!strncmp(arg,"--clientinterface=",18)) {
			if (!inet_aton(arg+18,&inaddr)) GOTOERROR;
			clientaddr=inaddr.s_addr;
		} else if (!strncmp(arg,"--socketname=",13)) {
		} else if (!strncmp(arg,"--keyfile=",10)) {
			keyfile=arg+10;
		} else if (!strncmp(arg,"--certfile=",11)) {
			certfile=arg+11;
		} else if (!strncmp(arg,"--port=",7)) {
			tunnelport=(unsigned short)slowtou(arg+7);
		} else if (!strncmp(arg,"--maxtunnels=",13)) {
			maxtunnels=(unsigned short)slowtou(arg+13);
		} else if (!strcmp(arg,"--notroot")) { // handled before
		} else if (!strcmp(arg,"--verbose")) { // handled before
		} else if (!strcmp(arg,"--debug")) { // handled before
		} else if (!strcmp(arg,"--help")) {
			fprintf(stdout,"Warning! You need to allow clients before a tunnel connects.\n"); 
			fprintf(stdout,"If you add a client IP, you should kill waiting tunnel pids to reload the client list.\n");
			fprintf(stdout,"--notroot: run as non-root user\n");
			fprintf(stdout,"--socketname=FILENAME: filename to use for local control socket\n");
			fprintf(stdout,"  default is %s for root, %s if not root\n",ROOT_CPATH,NOTROOT_CPATH);
			fprintf(stdout,"--debug: run in foreground\n");
			fprintf(stdout,"--verbose: print more status messages\n");
			fprintf(stdout,"Server-only commands:\n");
			fprintf(stdout,"  --password=HEXPASS16: set the connection password, 16 hex chars\n");
			fprintf(stdout,"  --clientinterface=IP: IP to restrict clients to a single interface\n");
			fprintf(stdout,"  --port=PORT : bind to PORT for tunnel connections\n");
			fprintf(stdout,"  --maxtunnels=NUMBER : limit the number of simultaneous tunnels\n");
			fprintf(stdout,"  --keyfile=FILENAME : private key for TLS, default is %s\n",keyfile);
			fprintf(stdout,"    e.g. \"certtool --generate-privkey --outfile fixed.key\"\n");
			fprintf(stdout,"  --certfile=FILENAME : certificate for TLS, default is %s\n",certfile);
			fprintf(stdout,"    e.g. \"certtool --generate-self-signed --load-privkey fixed.key --outfile fixed.cert\"\n");
			fprintf(stdout,"Configuration-only commands (connects to running process):\n");
			fprintf(stdout,"  --list-tunnels: current authenticated tunnels \n");
			fprintf(stdout,"  --list-allowed-tunnels: IPs allowed for remote connections\n");
			fprintf(stdout,"  --list-allowed-clients: IPs allowed for local connections\n");
			fprintf(stdout,"  --lastip-client: the last local IP that tried to connect\n");
			fprintf(stdout,"  --lastip-tunnel: the last remote IP that tried to connect\n");
			fprintf(stdout,"  --addip-tunnel=IP: allow IP to connect\n");
			fprintf(stdout,"  --addip-client=IP: allow IP to connect\n");
			_exit(0);
		} else {
			fprintf(stdout,"%s:%d unknown argument %s, try --help\n",__FILE__,__LINE__,arg);
			GOTOERROR;
		}
		if (cmd_arg) {
			isserver=0;
			if (reinit_log(&log,stderr,0,loglevels)) GOTOERROR;
			if (handlecontrolcommand(&log,cpath,cmd_arg,ipv4_arg)) GOTOERROR;
		}
	}
}

if (isserver) {
	if (!tunnelport) {
		tunnelport=isnotroot?NOTROOT_TUNNELPORT:ROOT_TUNNELPORT;
	}
	if (isfork) {
		pid_t pid;
		pid=fork();
		if (pid<0) GOTOERROR;
		if (!pid) {
			if (reinit_log(&log,NULL,1,loglevels)) GOTOERROR;
			if (mainloop(&log,password8,keyfile,certfile,maxtunnels,0,tunnelport,clientaddr,cpath,isnobody)) GOTOERROR;
		}
	} else {
		if (init_log(&log,stderr,0,loglevels)) GOTOERROR;
		if (mainloop(&log,password8,keyfile,certfile,maxtunnels,0,tunnelport,clientaddr,cpath,isnobody)) GOTOERROR;
	}
}
deinit_log(&log);
return 0;
error:
	deinit_log(&log);
	return -1;
}
