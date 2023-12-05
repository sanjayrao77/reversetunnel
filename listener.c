/*
 * listener.c - wait for connections from dynamic side
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
#define DEBUG
#include "common/conventions.h"
#include "common/blockmem.h"
#include "magic.h"
#include "misc.h"

#include "listener.h"

static int nodelay_net(int fd) {
int yesint=1;
return setsockopt(fd,IPPROTO_TCP,TCP_NODELAY, (char*)&yesint,sizeof(int));
}

void clear_listener(struct listener *f) {
static struct listener blank={.sockets.tunnel=-1,.sockets.client=-1,.sockets.tcp_tunnel=-1,.sockets.tcp_client=-1};
*f=blank;
}
void deinit_listener(struct listener *f) {
ifclose(f->sockets.tunnel);
ifclose(f->sockets.client);
ifclose(f->sockets.tcp_tunnel);
ifclose(f->sockets.tcp_client);
deinit_blockmem(&f->blockmem);
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

int init_listener(struct listener *f, int tunnelport, uint32_t tunneladdress, int clientport, uint32_t clientaddress,
		unsigned char *password8) {
int fd1=-1,fd2=-1;

if (getsocket(&fd1,tunnelport,tunneladdress))  GOTOERROR;
if (getsocket(&fd2,clientport,clientaddress))  GOTOERROR;
if (init_blockmem(&f->blockmem,0)) GOTOERROR;

memcpy(f->password8,password8,8);
f->sockets.tunnel=fd1;
f->sockets.client=fd2;
return 0;
error:
	ifclose(fd1);
	ifclose(fd2);
	return -1;
}

static int ignoreclient(int lfd) {
int fd=-1;
fd=accept(lfd,NULL,NULL);
if (fd>=0) (ignore)close(fd);
return 0;
}

static int isauthorized_tunnel(struct listener *f, uint32_t ipv4) {
struct oneipv4_listener *oneipv4;

oneipv4=f->authorized.tunnel.first;
if (!oneipv4) return 1;
while (1) {
	if (oneipv4->ipv4==ipv4) return 1;
	oneipv4=oneipv4->next;
	if (!oneipv4) break;
}
return 0;
}
static int isauthorized_client(struct listener *f, uint32_t ipv4) {
struct oneipv4_listener *oneipv4;

oneipv4=f->authorized.client.first;
if (!oneipv4) return 1;
while (1) {
	if (oneipv4->ipv4==ipv4) return 1;
	oneipv4=oneipv4->next;
	if (!oneipv4) break;
}
return 0;
}

static int accepttunnel(struct listener *f) {
struct sockaddr_in sa;
unsigned char buff24[24];
socklen_t ssa;
int fd=-1;

ssa=sizeof(sa);
fd=accept(f->sockets.tunnel,(struct sockaddr*)&sa,&ssa);
if (fd<0) goto noerror;
if (ssa!=sizeof(sa)) goto noerror;
if (!isauthorized_tunnel(f,sa.sin_addr.s_addr)) goto noerror;
if (timeout_readn(fd,buff24,24,time(NULL)+10)) {
	fprintf(stderr,"%s:%d timeout waiting for client handshake\n",__FILE__,__LINE__);
	goto noerror;
}
if (memcmp(buff24,HELLO8_TUNNEL,8)) goto noerror;
if (memcmp(buff24+8,f->password8,8)) goto noerror;
// buff24+16 holds 8 bytes of hostname
(ignore)nodelay_net(fd);
f->sockets.tcp_tunnel=fd;
return 0;
noerror:
	ifclose(fd);
	return 0;
}

static int acceptclient(struct listener *f) {
struct sockaddr_in sa;
socklen_t ssa;
int fd=-1;

ssa=sizeof(sa);
fd=accept(f->sockets.client,(struct sockaddr*)&sa,&ssa);
if (fd<0) goto noerror;
if (ssa!=sizeof(sa)) goto noerror;
if (!isauthorized_client(f,sa.sin_addr.s_addr)) goto noerror;
(ignore)nodelay_net(fd);
f->sockets.tcp_client=fd;
return 0;
noerror:
	ifclose(fd);
	return 0;
}

int waitfortunnel_listener(struct listener *f) {
struct pollfd pollfds[2];
pollfds[0].fd=f->sockets.tunnel;
pollfds[0].events=POLLIN;
pollfds[1].fd=f->sockets.client;
pollfds[1].events=POLLIN;

while (1) {
	switch (poll(pollfds,2,-1)) {
		case -1:
			if (errno==EINTR) continue;
			GOTOERROR;
		case 0: continue;
	}
	if (pollfds[1].revents&POLLIN) {
		if (ignoreclient(f->sockets.client)) GOTOERROR;
	}
	if (pollfds[0].revents&POLLIN) {
		if (accepttunnel(f)) GOTOERROR;
		if (f->sockets.tcp_tunnel>=0) break;
	}
}
return 0;
error:
	return -1;
}

int waitforclient_listener(struct listener *f) {
// we have tcp_tunnel, waiting for client connect
struct pollfd pollfds[2];
pollfds[0].fd=f->sockets.tcp_tunnel;
pollfds[0].events=POLLIN;
pollfds[1].fd=f->sockets.client;
pollfds[1].events=POLLIN;

while (1) {
	switch (poll(pollfds,2,-1)) {
		case -1:
			if (errno==EINTR) continue;
			GOTOERROR;
		case 0: continue;
	}
	if (pollfds[0].revents&POLLIN) {
		(ignore)close(f->sockets.tcp_tunnel);
		f->sockets.tcp_tunnel=-1;
		break;
	}
	if (pollfds[1].revents&POLLIN) {
		if (acceptclient(f)) GOTOERROR;
		if (f->sockets.tcp_client>=0) break;
	}
}
return 0;
error:
	return -1;
}

void closeclients_listener(struct listener *f) {
int fd;
fd=f->sockets.tcp_tunnel;
if (fd>=0) {
	(ignore)close(fd);
	f->sockets.tcp_tunnel=-1;
}
fd=f->sockets.tcp_client;
if (fd>=0) {
	(ignore)close(fd);
	f->sockets.tcp_client=-1;
}
}

int proxyclients_listener(struct listener *f) {
// this is copied in proxyclients_connector
unsigned char buffer1[512],buffer0[512],*ptr1=NULL,*ptr0=NULL;
struct pollfd pollfds[2];
unsigned int num1=0,num0=0;
int fd1,fd0;

if (0>(fd1=f->sockets.tcp_client)) return 0;
if (0>(fd0=f->sockets.tcp_tunnel)) return 0;

pollfds[0].fd=fd0;
pollfds[1].fd=fd1;

while (1) {
	int k;
	if (num1) pollfds[0].events=POLLOUT;
	else if (!num0) pollfds[0].events=POLLIN;
	else pollfds[0].events=0;
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
			k=read(fd0,ptr0,512);
//			fprintf(stderr,"%s:%d read %d bytes from tunnel\n",__FILE__,__LINE__,k);
			if (k<=0) {
				if (!k) break;
				if (errno==EINTR) continue;
				goto noerror;
			}
			num0=(unsigned int)k;
		} else if (pollfds[0].revents&POLLOUT) {
			k=write(fd0,ptr1,num1);
//			fprintf(stderr,"%s:%d wrote %d bytes to tunnel\n",__FILE__,__LINE__,k);
			if (k<0) {
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
//			fprintf(stderr,"%s:%d read %d bytes from client\n",__FILE__,__LINE__,k);
			if (k<=0) {
				if (!k) break;
				if (errno==EINTR) continue;
				goto noerror;
			}
			num1=(unsigned int)k;
		} else if (pollfds[1].revents&POLLOUT) {
			k=write(fd1,ptr0,num0);
//			fprintf(stderr,"%s:%d wrote %d bytes to client\n",__FILE__,__LINE__,k);
			if (k<0) {
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

int add_tunnel_authorized_listener(struct listener *f, uint32_t ipv4) {
struct oneipv4_listener *oneipv4;
if (!(oneipv4=ALLOC_blockmem(&f->blockmem,struct oneipv4_listener))) GOTOERROR;
oneipv4->ipv4=ipv4;
oneipv4->next=f->authorized.tunnel.first;
f->authorized.tunnel.first=oneipv4;
return 0;
error:
	return -1;
}
int add_client_authorized_listener(struct listener *f, uint32_t ipv4) {
struct oneipv4_listener *oneipv4;
if (!(oneipv4=ALLOC_blockmem(&f->blockmem,struct oneipv4_listener))) GOTOERROR;
oneipv4->ipv4=ipv4;
oneipv4->next=f->authorized.client.first;
f->authorized.client.first=oneipv4;
return 0;
error:
	return -1;
}
