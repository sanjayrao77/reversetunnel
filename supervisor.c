/*
 * supervisor.c - bridge between two tcp sockets we've listened for
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
#include <netinet/tcp.h> // for NODELAY
#include <sys/mman.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/wait.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#define DEBUG
#include "common/conventions.h"
#include "common/blockmem.h"
#include "tls.h"
#include "magic.h"
#include "misc.h"
#include "log.h"
#include "control.h"

#include "supervisor.h"

static int nodelay_net(int fd) {
int yesint=1;
return setsockopt(fd,IPPROTO_TCP,TCP_NODELAY, (char*)&yesint,sizeof(int));
}

void clear_supervisor(struct supervisor *s) {
static struct supervisor blank={.sockets.unix_control=-1,.sockets.tunnel=-1,.shared.entries=MAP_FAILED,
		.tls.fd=-1};
*s=blank;
}

void deinit_supervisor(struct supervisor *s) {
ifclose(s->sockets.unix_control);
ifclose(s->sockets.tunnel);
if (s->tofree.mmap!=MAP_FAILED) {
	if (s->shared.common && s->shared.common->isinit) {
		(ignore)pthread_mutex_destroy(&s->shared.common->mainlock);
	}
	(ignore)munmap(s->tofree.mmap,s->tofree.mmaplength);
}
deinit_tls(&s->tls);
}

static int getsocket(int *fd_out, short port, uint32_t address) {
struct sockaddr_in sa;
int fd=-1;
int fuse=60;

memset(&sa,0,sizeof(sa));
sa.sin_family=AF_INET;
sa.sin_port=htons(port);
sa.sin_addr.s_addr=address;

if (0>(fd=socket(AF_INET,SOCK_STREAM,0))) GOTOERROR;

while (1) {
	int r;
	r=bind(fd,(struct sockaddr*)&sa,sizeof(sa));
	if (!r) break;
	if (errno==EINTR) continue;
	if (errno==EADDRINUSE) {
		if (!fuse) GOTOERROR;
		fuse--;
		sleep(5);
		continue;
	}
	GOTOERROR;
}

if (listen(fd,5)) GOTOERROR;

*fd_out=fd;
return 0;
error:
	ifclose(fd);
	return -1;
}

static int makelistenunix(int *fd_out, char *socketname) {
struct sockaddr_un su;
int fd=-1;
int namelen;
int retryfuse=30;

memset(&su,0,sizeof(struct sockaddr_un));
su.sun_family=PF_UNIX;
namelen=strlen(socketname)+1;
if (namelen>sizeof(su.sun_path)) GOTOERROR;
memcpy(su.sun_path,socketname,namelen);

fd=socket(AF_UNIX,SOCK_STREAM,0);
if (fd<0) goto error;
while (1) {
	int r;
	(ignore)unlink(socketname);
	r=bind(fd,(struct sockaddr*)&su,sizeof(struct sockaddr_un));
	if (!r) break;
	if (!retryfuse) GOTOERROR;
	retryfuse--;
	sleep(30);
}
if (listen(fd,5)) GOTOERROR;
*fd_out=fd;
return 0;
error:
	ifclose(fd);
	return -1;
}

int init_supervisor(struct supervisor *s, struct log *log, unsigned int maxentries, uint32_t ifaddr_tunnel, unsigned short port_tunnel,
		uint32_t ifaddr_client, unsigned char *password8, char *keyfile, char *certfile) {
pthread_mutexattr_t attr;
int isattrinit=0;

s->log=log;
if (!maxentries) GOTOERROR;
if (init_tls(&s->tls,log,NULL,keyfile,certfile,1)) GOTOERROR;
if (init_blockmem(&s->blockmem,0)) GOTOERROR;
if (getsocket(&s->sockets.tunnel,port_tunnel,ifaddr_tunnel)) GOTOERROR;
s->tofree.mmaplength=sizeof(struct common_supervisor)+maxentries*sizeof(struct entry_supervisor);
s->tofree.mmap=mmap(NULL,s->tofree.mmaplength,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
if (s->tofree.mmap==MAP_FAILED) GOTOERROR;
memset(s->tofree.mmap,0,s->tofree.mmaplength);
s->shared.common=s->tofree.mmap;
s->shared.entries=s->tofree.mmap+sizeof(struct common_supervisor);

if (pthread_mutexattr_init(&attr)) GOTOERROR;
isattrinit=1;
// if (pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_DEFAULT)) GOTOERROR;
if (pthread_mutex_init(&s->shared.common->mainlock,&attr)) GOTOERROR;
s->shared.common->isinit=1;

memcpy(s->config.password8,password8,8);
s->config.port=port_tunnel;
s->config.ifaddr_client=ifaddr_client;
s->config.isdenyall_tunnel=1;
s->config.isdenyall_client=1;
s->shared.max=maxentries;

(ignore)pthread_mutexattr_destroy(&attr);
return 0;
error:
	if (isattrinit) (ignore)pthread_mutexattr_destroy(&attr);
	return -1;
}

int addcontrol_supervisor(struct supervisor *s, char *path) {
if (s->sockets.unix_control>=0) GOTOERROR;
if (makelistenunix(&s->sockets.unix_control,path)) GOTOERROR;
return 0;
error:
	return -1;
}

static struct oneipv4_supervisor *alloc_oneipv4_supervisor(struct supervisor *f) {
struct oneipv4_supervisor *oneip;
oneip=f->recycle.first_oneipv4;
if (oneip) {
	f->recycle.first_oneipv4=oneip->next;
	return oneip;
}
if (!(oneip=ALLOC_blockmem(&f->blockmem,struct oneipv4_supervisor))) GOTOERROR;
return oneip;
error:
	return NULL;
}

int add_tunnel_authorized_supervisor(struct supervisor *f, uint32_t ipv4) {
struct oneipv4_supervisor *oneipv4;
if (!(oneipv4=alloc_oneipv4_supervisor(f))) GOTOERROR;
oneipv4->ipv4=ipv4;
oneipv4->next=f->authorized.tunnel.first;
f->authorized.tunnel.first=oneipv4;
return 0;
error:
	return -1;
}
int add_client_authorized_supervisor(struct supervisor *f, uint32_t ipv4) {
struct oneipv4_supervisor *oneipv4;
if (!(oneipv4=alloc_oneipv4_supervisor(f))) GOTOERROR;
oneipv4->ipv4=ipv4;
oneipv4->next=f->authorized.client.first;
f->authorized.client.first=oneipv4;
return 0;
error:
	return -1;
}

static int ignoreclient(int lfd) {
int fd=-1;
fd=accept(lfd,NULL,NULL);
if (fd>=0) (ignore)close(fd);
return 0;
}

static int isauthorized_tunnel(struct supervisor *f, uint32_t ipv4) {
struct oneipv4_supervisor *oneipv4;

oneipv4=f->authorized.tunnel.first;
if (!oneipv4) {
	if (f->config.isdenyall_tunnel) return 0;
	return 1;
}
while (1) {
	if (oneipv4->ipv4==ipv4) return 1;
	oneipv4=oneipv4->next;
	if (!oneipv4) break;
}
return 0;
}

static int accepttunnel(int *fd_out, uint32_t *ipv4_out, struct supervisor *f) {
struct sockaddr_in sa;
unsigned char buff8[8];
socklen_t ssa;
uint32_t ipv4;
int fd=-1;

ssa=sizeof(sa);
fd=accept(f->sockets.tunnel,(struct sockaddr*)&sa,&ssa);
if (fd<0) goto noerror;
if (ssa!=sizeof(sa)) goto noerror;
ipv4=sa.sin_addr.s_addr;
(ignore)message_log(f->log,NORMAL_LOG,"%s:%d got accept from tunnel %u.%u.%u.%u\n",__FILE__,__LINE__,
		ipv4&0xff, (ipv4>>8)&0xff, (ipv4>>16)&0xff, (ipv4>>24)&0xff);
if (!isauthorized_tunnel(f,ipv4)) {
	f->authorized.tunnel.ipv4_lastblocked=ipv4;
	goto noerror;
}
if (timeout_readn(fd,buff8,8,time(NULL)+10)) {
	(ignore)message_log(f->log,VERBOSE_LOG,"%s:%d timeout waiting for client handshake\n",__FILE__,__LINE__);
	goto noerror;
}
if (memcmp(buff8,HELLO8_TUNNEL,8)) goto noerror;
*fd_out=fd;
*ipv4_out=ipv4;
return 0;
noerror:
	ifclose(fd);
	*fd_out=-1;
	return 0;
}

static int locked_pickentryindex(struct supervisor *s) {
// lock mainlock before calling
unsigned int max;
struct entry_supervisor *entries;
int idx=0;

max=s->shared.max;
entries=s->shared.entries;
while (1) {
	if (!entries->isactive) {
		break;
	}
	max--;
	if (!max) return -1;
	entries+=1;
	idx+=1;
}

return idx;
}

static char *staticstring_ipv4(uint32_t ipv4) {
static char str[16];
snprintf(str,16,"%u.%u.%u.%u",ipv4&0xff, (ipv4>>8)&0xff, (ipv4>>16)&0xff, (ipv4>>24)&0xff);
return str;
}

static int isauthorized_client(struct supervisor *f, uint32_t ipv4) {
struct oneipv4_supervisor *oneipv4;

oneipv4=f->authorized.client.first;
if (!oneipv4) {
	if (f->config.isdenyall_client) return 0;
	return 1;
}
while (1) {
	if (oneipv4->ipv4==ipv4) return 1;
	oneipv4=oneipv4->next;
	if (!oneipv4) break;
}
return 0;
}

static int proxyclients(struct supervisor *s, int tcp_client) {
// this is copied in proxyclients_connector
unsigned char buffer1[512],buffer0[512],*ptr1=NULL,*ptr0=NULL;
struct pollfd pollfds[2];
unsigned int num1=0,num0=0;
int fd1,fd0;
gnutls_session_t sess;

if (0>(fd1=tcp_client)) return 0;
if (0>(fd0=s->tls.fd)) return 0;

sess=s->tls.tlssession;

pollfds[0].fd=fd0;
pollfds[1].fd=fd1;

while (1) {
	int k;
	if (num1) pollfds[0].events=POLLOUT;
	else if (!num0) {
		if (gnutls_record_check_pending(sess)) {
			ptr0=buffer0;
			k=gnutls_record_recv(sess,ptr0,512);
			switch (k) {
				case GNUTLS_E_REHANDSHAKE:
					if (gnutls_alert_send(sess,GNUTLS_AL_WARNING,GNUTLS_A_NO_RENEGOTIATION)) goto noerror; // no break
				case GNUTLS_E_AGAIN:
				case GNUTLS_E_INTERRUPTED:
					continue;
			}
			if (k<=0) {
				if (!k) break;
				goto noerror;
			}
			num0=(unsigned int)k;
			continue;
		} else {
			pollfds[0].events=POLLIN;
		}
	} else pollfds[0].events=0;
	if (num0) pollfds[1].events=POLLOUT;
	else if (!num1) pollfds[1].events=POLLIN;
	else pollfds[1].events=0;

	switch (poll(pollfds,2,1000*60*10)) {
		case 0: goto timeout;
		case -1: if (errno==EINTR) continue; goto noerror; break;
	}
	if (pollfds[0].revents) {
		if (pollfds[0].revents&POLLIN) {
			ptr0=buffer0;
			k=gnutls_record_recv(sess,ptr0,512);
			switch (k) {
				case GNUTLS_E_REHANDSHAKE:
					if (gnutls_alert_send(sess,GNUTLS_AL_WARNING,GNUTLS_A_NO_RENEGOTIATION)) goto noerror; // no break
				case GNUTLS_E_AGAIN:
				case GNUTLS_E_INTERRUPTED:
					continue;
			}
			if (k<=0) {
				if (!k) break;
				goto noerror;
			}
			num0=(unsigned int)k;
		} else if (pollfds[0].revents&POLLOUT) {
			k=gnutls_record_send(sess,ptr1,num1);
			switch (k) {
				case GNUTLS_E_AGAIN:
				case GNUTLS_E_INTERRUPTED:
					continue;
			}
			if (k<=0) {
				if (!k) break;
				if (errno==EINTR) continue;
				goto noerror;
			}
			num1-=(unsigned int)k;
			ptr1+=num1;
		}
	}
	if (pollfds[1].revents) {
		if (pollfds[1].revents&POLLIN) {
			ptr1=buffer1;
			k=read(fd1,ptr1,512);
			if (k<=0) {
				if (!k) break;
				if (errno==EINTR) continue;
				goto noerror;
			}
			num1=(unsigned int)k;
		} else if (pollfds[1].revents&POLLOUT) {
			k=write(fd1,ptr0,num0);
			if (k<=0) {
				if (!k) break;
				if (errno==EINTR) continue;
				goto noerror;
			}
			num0-=(unsigned int)k;
			ptr0+=num0;
		}
	}
}

return 0;
timeout:
	return 0;
noerror:
	return 0;
}

static int acceptclient(int *fd_out, struct supervisor *s, int client) {
struct sockaddr_in sa;
socklen_t ssa;
int fd=-1;

ssa=sizeof(sa);
fd=accept(client,(struct sockaddr*)&sa,&ssa);
if (fd<0) goto noerror;
if (ssa!=sizeof(sa)) goto noerror;
{
	uint32_t ipv4;
	ipv4=sa.sin_addr.s_addr;
	(ignore)message_log(s->log,NORMAL_LOG,"%s:%d got accept from client %u.%u.%u.%u\n",__FILE__,__LINE__,
			ipv4&0xff, (ipv4>>8)&0xff, (ipv4>>16)&0xff, (ipv4>>24)&0xff);
}
if (!isauthorized_client(s,sa.sin_addr.s_addr)) {
	(ignore)message_log(s->log,VERBOSE_LOG,"%s:%d client is not from allowed address\n",__FILE__,__LINE__);
	(ignore)pthread_mutex_lock(&s->shared.common->mainlock);
		s->shared.common->client.ipv4_lastblocked=sa.sin_addr.s_addr;
	(ignore)pthread_mutex_unlock(&s->shared.common->mainlock);
	goto noerror;
}
(ignore)nodelay_net(fd);
*fd_out=fd;
return 0;
noerror:
	ifclose(fd);
	return 0;
}

static int waitforclient(int *fd_out, struct supervisor *s, int client) {
// we have tcp_tunnel, waiting for client connect
struct pollfd pollfds[2];
int tcp_client=-1;

pollfds[0].fd=s->tls.fd;
pollfds[0].events=POLLIN;
pollfds[1].fd=client;
pollfds[1].events=POLLIN;

if (gnutls_record_check_pending(s->tls.tlssession)) GOTOERROR;

while (1) {
	switch (poll(pollfds,2,1000*60*10)) {
		case -1:
			if (errno==EINTR) continue;
			GOTOERROR;
		case 0:
			if (timeout_writen_tls(&s->tls,(unsigned char *)"00000001",8,time(NULL)+10)) GOTOERROR; // keepalive
			continue;
	}
	if (pollfds[0].revents&POLLIN) {
//		if (gnutls_record_check_pending(s->tls.tlssession)) GOTOERROR;
		goto error; // this could just be a shutdown
	}
	if (pollfds[1].revents&POLLIN) {
		if (acceptclient(&tcp_client,s,client)) GOTOERROR;
		if (tcp_client>=0) break;
	}
}

*fd_out=tcp_client;
return 0;
error:
	ifclose(tcp_client);
	return -1;
}

static int handlechild(struct supervisor *s, struct entry_supervisor *entry, int tcp_tunnel, uint32_t ipv4_tunnel) {
struct sockaddr_in sa;
int client=-1,tcp_client=-1;
unsigned short port=0;
unsigned char buff16[16];
unsigned char hostname8[8];

(ignore)nodelay_net(tcp_tunnel);

if (timeout_writen(tcp_tunnel,(unsigned char *)HELLO8_TUNNEL,8,time(NULL)+30)) GOTOERROR;
if (startsession_tls(&s->tls,NULL,tcp_tunnel)) GOTOERROR;
tcp_tunnel=-1;
if (timeout_readn_tls(&s->tls,buff16,16,time(NULL)+10)) {
	goto error;
}

if (memcmp(buff16,s->config.password8,8)) {
	(ignore)message_log(s->log,NORMAL_LOG,"%s:%d bad password from client %s\n",__FILE__,__LINE__,staticstring_ipv4(ipv4_tunnel));
	goto error;
}
memcpy(hostname8,buff16+8,8);

client=socket(AF_INET,SOCK_STREAM,0);
if (0>client) GOTOERROR;

memset(&sa,0,sizeof(sa));
sa.sin_family=AF_INET;
sa.sin_addr.s_addr=s->config.ifaddr_client;

while (1) {
	if (0>bind(client,(struct sockaddr*)&sa,sizeof(sa))) {
		if (errno==EINTR) continue;
		GOTOERROR;
	}
	break;
}
{
	socklen_t ssa;
	ssa=sizeof(sa);
	if (getsockname(client,(struct sockaddr*)&sa,&ssa)) GOTOERROR;
	if (ssa==sizeof(sa)) {
		port=ntohs(sa.sin_port);
	}
}
if (listen(client,5)) GOTOERROR;

(ignore)pthread_mutex_lock(&s->shared.common->mainlock);
	memcpy(entry->hostname8,hostname8,8);
	entry->port=port;
(ignore)pthread_mutex_unlock(&s->shared.common->mainlock);

(ignore)message_log(s->log,VERBOSE_LOG,"%s:%d listening for client on %s:%u\n",__FILE__,__LINE__,
		staticstring_ipv4(s->config.ifaddr_client),port);

if (waitforclient(&tcp_client,s,client)) GOTOERROR;
if (0>tcp_client) GOTOERROR;

{ // wake up tunnel by sending start
	if (timeout_writen_tls(&s->tls,(unsigned char *)"00000002",8,time(NULL)+10)) GOTOERROR;
}

if (proxyclients(s,tcp_client)) GOTOERROR;

close(client);
return 0;
error:
	ifclose(client);
	ifclose(tcp_client);
	return -1;
}

static int fork_tunnel(struct supervisor *s, int fd, uint32_t ipv4) {
int eidx;
pid_t pid;
struct entry_supervisor *entry;

(ignore)pthread_mutex_lock(&s->shared.common->mainlock);

	eidx=locked_pickentryindex(s);
	if (eidx<0) { // this shouldn't happen as we've already checked max!=numactive
(ignore)pthread_mutex_unlock(&s->shared.common->mainlock);
		GOTOERROR;
	}
	entry=&s->shared.entries[eidx];
	pid=fork();
	if (!pid) {
		(ignore)handlechild(s,entry,fd,ipv4);
		_exit(0);
	}
	if (pid<0) {
(ignore)pthread_mutex_unlock(&s->shared.common->mainlock);
		GOTOERROR;
	}

	entry->isactive=1;
	entry->pid=pid;
	entry->timestamp=(uint64_t)time(NULL);
	entry->ipv4=ipv4;
	memset(entry->hostname8,0,8);
	entry->port=0;

(ignore)pthread_mutex_unlock(&s->shared.common->mainlock);

s->shared.numactive+=1;

return 0;
error:
	return -1;
}

static int handletunnel(struct supervisor *s) {
uint32_t ipv4;
int fd=-1;
if (s->shared.max==s->shared.numactive) {
	(ignore)message_log(s->log,VERBOSE_LOG,"%s:%d max tunnels reached (%u), ignoring new tunnel\n",__FILE__,__LINE__,s->shared.max);
	return ignoreclient(s->sockets.tunnel);
}
if (accepttunnel(&fd,&ipv4,s)) GOTOERROR;
if (fd>=0) {
	(ignore)fork_tunnel(s,fd,ipv4);
	(ignore)close(fd);
}
return 0;
error:
	ifclose(fd);
	return -1;
}

static int list_authorized_control(struct supervisor *s, int fd, struct oneipv4_supervisor *oneipv4) {
struct cmd_control cmd;

while (oneipv4) {
	cmd.type=ONEIP_TYPE_CMD_CONTROL;
	cmd.oneip.ipv4=oneipv4->ipv4;
	if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;

	oneipv4=oneipv4->next;
}

cmd.type=TERMINATOR_TYPE_CMD_CONTROL;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;
return 0;
error:
	return -1;
}

static int list_tunnels_control(struct supervisor *s, int fd) {
struct entry_supervisor *entries;
unsigned int max;
struct cmd_control cmd;

cmd.type=ONETUNNEL_TYPE_CMD_CONTROL;

(ignore)pthread_mutex_lock(&s->shared.common->mainlock);
	max=s->shared.max;
	entries=s->shared.entries;
	while (1) {
		if (entries->isactive) {
			cmd.onetunnel.pid=entries->pid;
			cmd.onetunnel.timestamp=entries->timestamp;
			cmd.onetunnel.ipv4=entries->ipv4;
			memcpy(cmd.onetunnel.hostname8,entries->hostname8,8);
			cmd.onetunnel.port=entries->port;
			if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) {
(ignore)pthread_mutex_unlock(&s->shared.common->mainlock);
				GOTOERROR;
			}
		}
		max--;
		if (!max) break;
		entries+=1;
	}
(ignore)pthread_mutex_unlock(&s->shared.common->mainlock);

cmd.type=TERMINATOR_TYPE_CMD_CONTROL;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;
return 0;
error:
	return -1;
}

static int lastip_tunnel_control(struct supervisor *s, int fd) {
struct cmd_control cmd;

cmd.type=ONEIP_TYPE_CMD_CONTROL;
cmd.oneip.ipv4=s->authorized.tunnel.ipv4_lastblocked;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;

cmd.type=TERMINATOR_TYPE_CMD_CONTROL;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;
return 0;
error:
	return -1;
}

static int lastip_client_control(struct supervisor *s, int fd) {
struct cmd_control cmd;

cmd.type=ONEIP_TYPE_CMD_CONTROL;
(ignore)pthread_mutex_lock(&s->shared.common->mainlock);
	cmd.oneip.ipv4=s->shared.common->client.ipv4_lastblocked;
(ignore)pthread_mutex_unlock(&s->shared.common->mainlock);
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;

cmd.type=TERMINATOR_TYPE_CMD_CONTROL;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;
return 0;
error:
	return -1;
}

static int addip_tunnel_control(struct supervisor *s, uint32_t ipv4, int fd) {
struct cmd_control cmd;

if (add_tunnel_authorized_supervisor(s,ipv4)) GOTOERROR;

cmd.type=ONEIP_TYPE_CMD_CONTROL;
cmd.oneip.ipv4=ipv4;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;

cmd.type=TERMINATOR_TYPE_CMD_CONTROL;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;
return 0;
error:
	return -1;
}

static int addip_client_control(struct supervisor *s, uint32_t ipv4, int fd) {
struct cmd_control cmd;

if (add_client_authorized_supervisor(s,ipv4)) GOTOERROR;

cmd.type=ONEIP_TYPE_CMD_CONTROL;
cmd.oneip.ipv4=ipv4;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;

cmd.type=TERMINATOR_TYPE_CMD_CONTROL;
if (timeout_writen(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) GOTOERROR;
return 0;
error:
	return -1;
}

static int handlecontrol(struct supervisor *s) {
struct cmd_control cmd;
int fd=-1;
fd=accept(s->sockets.unix_control,NULL,NULL);
if (fd<0) goto noerror;
if (timeout_readn(fd,(unsigned char *)&cmd,sizeof(cmd),time(NULL)+10)) goto noerror;
switch (cmd.type) {
	case LIST_AUTHORIZED_TUNNEL_TYPE_CMD_CONTROL:
		if (list_authorized_control(s,fd,s->authorized.tunnel.first)) goto noerror;
		break;
	case LIST_AUTHORIZED_CLIENT_TYPE_CMD_CONTROL:
		if (list_authorized_control(s,fd,s->authorized.client.first)) goto noerror;
		break;
	case LIST_TUNNELS_TYPE_CMD_CONTROL:
		if (list_tunnels_control(s,fd)) goto noerror;
		break;
	case LASTIP_TUNNEL_TYPE_CMD_CONTROL:
		if (lastip_tunnel_control(s,fd)) goto noerror;
		break;
	case LASTIP_CLIENT_TYPE_CMD_CONTROL:
		if (lastip_client_control(s,fd)) goto noerror;
		break;
	case ADDIP_TUNNEL_TYPE_CMD_CONTROL:
		if (addip_tunnel_control(s,cmd.oneip.ipv4,fd)) goto noerror;
		break;
	case ADDIP_CLIENT_TYPE_CMD_CONTROL:
		if (addip_client_control(s,cmd.oneip.ipv4,fd)) goto noerror;
		break;
}

close(fd);
return 0;
noerror:
	ifclose(fd);
	return 0;
}

static void removechild(struct supervisor *s, pid_t pid) {
unsigned int max;
struct entry_supervisor *entries;

if (!s->shared.numactive) return;

(ignore)pthread_mutex_lock(&s->shared.common->mainlock);
	max=s->shared.max;
	entries=s->shared.entries;
	while (1) {
		if (entries->isactive && (entries->pid==pid)) {
			s->shared.numactive-=1;
			entries->isactive=0;
			break;
		}
		max--;
		if (!max) break;
		entries+=1;
	}
(ignore)pthread_mutex_unlock(&s->shared.common->mainlock);

}

static void checkforzombies(struct supervisor *s) {
pid_t p;
while (1) {
	int wstatus;
	p=waitpid(-1,&wstatus,WNOHANG);
	if (p<=0) break;
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
		(void)removechild(s,p);
	}
}
}

int step_supervisor(struct supervisor *s) {
struct pollfd pollfds[2];
int npfds;

pollfds[0].fd=s->sockets.tunnel;
pollfds[0].events=POLLIN;
if (s->sockets.unix_control>=0) {
	pollfds[1].fd=s->sockets.unix_control;
	pollfds[1].events=POLLIN;
	npfds=2;
} else {
	pollfds[1].fd=-1;
	pollfds[1].events=0;
	pollfds[1].revents=0;
	npfds=1;
}
while (1) {
	(void)checkforzombies(s);
	switch (poll(pollfds,npfds,1000*60*10)) {
		case 0: continue;
		case -1: if (errno==EINTR) continue; GOTOERROR;
	}
	break;
}
if (pollfds[0].revents&POLLIN) {
	if (handletunnel(s)) GOTOERROR;
}
if (pollfds[1].revents&POLLIN) {
	if (handlecontrol(s)) GOTOERROR;
}
return 0;
error:
	return -1;
}
