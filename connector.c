/*
 * connector.c - bridge between two tcp sockets we've connected to
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
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#define DEBUG
#include "common/conventions.h"
#include "magic.h"
#include "misc.h"
#include "tls.h"
#include "log.h"

#include "connector.h"

void clear_connector(struct connector *c) {
static struct connector blank={.sockets.server=-1,.tls.fd=-1};
*c=blank;
}

void deinit_connector(struct connector *c) {
// ifclose(c->sockets.tunnel);
ifclose(c->sockets.server);
deinit_tls(&c->tls);
}

int init_connector(struct connector *c, struct log *log, uint32_t ipv4_tunnel, unsigned short port_tunnel,
		uint32_t ipv4_server, unsigned short port_server, unsigned char *password8, unsigned char *hostname8) {

c->log=log;

c->config.tunnel.ipv4=ipv4_tunnel;
c->config.tunnel.port=port_tunnel;
c->config.server.ipv4=ipv4_server;
c->config.server.port=port_server;
memcpy(c->password8,password8,8);
memcpy(c->hostname8,hostname8,8);
if (init_tls(&c->tls,log,NULL,NULL,NULL,0)) GOTOERROR;
return 0;
error:
	return -1;
}

static int nodelay_net(int fd) {
int yesint=1;
return setsockopt(fd,IPPROTO_TCP,TCP_NODELAY, (char*)&yesint,sizeof(int));
}

static char *staticstring_ipv4(uint32_t ipv4) {
static char str[16];
snprintf(str,16,"%u.%u.%u.%u",ipv4&0xff, (ipv4>>8)&0xff, (ipv4>>16)&0xff, (ipv4>>24)&0xff);
return str;
}

static int connecttoip(struct log *log, uint32_t ipv4, unsigned short port) {
struct sockaddr_in sa;
int fd=-1;
memset(&sa,0,sizeof(sa));
sa.sin_family=AF_INET;
sa.sin_addr.s_addr=ipv4;
sa.sin_port=htons(port);
fd=socket(AF_INET,SOCK_STREAM,0);
if (connect(fd,(struct sockaddr*)&sa,sizeof(sa))) {
	(ignore)message_log(log,VERBOSE_LOG,"%s:%d remote host is not listening on %s:%u\n",__FILE__,__LINE__,staticstring_ipv4(ipv4),port);
	GOTOERROR;
}
(ignore)nodelay_net(fd);
return fd;
error:
	ifclose(fd);
	return -1;
}

int connecttunnel_connector(struct connector *c) {
unsigned char buff24[24];
int fd=-1;
while (1) {
	fd=connecttoip(c->log,c->config.tunnel.ipv4,c->config.tunnel.port);
	if (fd>=0) break;
	sleep(30);
}

memcpy(buff24,HELLO8_TUNNEL,8);
memcpy(buff24+8,c->password8,8);
memcpy(buff24+16,c->hostname8,8);
if (timeout_writen(fd,buff24,8,time(NULL)+30)) {
	(ignore)message_log(c->log,VERBOSE_LOG,"%s:%d error sending HELLO\n",__FILE__,__LINE__);
	goto noerror;
}
if (timeout_readn(fd,buff24,8,time(NULL)+30)) {
	(ignore)message_log(c->log,VERBOSE_LOG,"%s:%d error receiving HELLO, maybe our IP isn't allowed\n",__FILE__,__LINE__);
	goto noerror;
}
if (memcmp(buff24,HELLO8_TUNNEL,8)) {
	(ignore)message_log(c->log,VERBOSE_LOG,"%s:%d HELLO doesn't match\n",__FILE__,__LINE__);
	goto noerror;
}

if (startsession_tls(&c->tls,NULL,fd)) {
	(ignore)message_log(c->log,VERBOSE_LOG,"%s:%d error starting TLS\n",__FILE__,__LINE__);
	goto noerror;
}
// c->sockets.tunnel=fd;
if (timeout_writen_tls(&c->tls,buff24+8,16,time(NULL)+30)) {
	(ignore)message_log(c->log,VERBOSE_LOG,"%s:%d error sending password\n",__FILE__,__LINE__);
	goto noerror;
}
return 0;
noerror:
	ifclose(fd);
	return -1;
}

int connectserver_connector(struct connector *c) {
int fd=-1;
// if (0>c->sockets.tunnel) return 0;
if (0>c->tls.fd) return 0;
fd=connecttoip(c->log,c->config.server.ipv4,c->config.server.port);
if (0>fd) goto noerror;
c->sockets.server=fd;
return 0;
noerror:
	ifclose(fd);
	return 0;
}

int proxyclients_connector(struct connector *c) {
// this is copied in proxyclients_listener
unsigned char buffer1[512],buffer0[512],*ptr1=NULL,*ptr0=NULL;
struct pollfd pollfds[2];
unsigned int num1=0,num0=0;
int fd1,fd0;
gnutls_session_t sess;

if (0>(fd1=c->sockets.server)) return 0;
if (0>(fd0=c->tls.fd)) return 0;

sess=c->tls.tlssession;

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

void reset_connector(struct connector *c) {
int fd;
reset_tls(&c->tls);
fd=c->sockets.server;
if (fd>=0) {
	(ignore)close(fd);
	c->sockets.server=-1;
}
}

int waitforclient_connector(struct connector *c) {
unsigned char msg8[8];

while (1) {
	if (timeout_readn_tls(&c->tls,msg8,8,time(NULL)+60*20)) GOTOERROR;
	if (!memcmp(msg8,"00000002",8)) break; // start
	if (!memcmp(msg8,"00000001",8)) continue; // keepalive
	GOTOERROR;
}

return 0;
error:
	return -1;
}
