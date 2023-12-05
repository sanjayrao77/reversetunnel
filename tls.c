/*
 * tls.c - wrapper for gnutls
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
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <poll.h>
#include <ctype.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#define DEBUG
#include "common/conventions.h"
#include "log.h"

#include "tls.h"

void clear_tls(struct tls *tls) {
static struct tls blank={.fd=-1};
*tls=blank;
}

int init_tls(struct tls *tls, struct log *log, char *cacertfilename, char *keyfilename, char *certfilename, int isserver) {
tls->log=log;
#if 0
tls->isdebug=1;
#endif
tls->isserver=isserver;
if (!tls->isglobalinit) {
	if (0>gnutls_global_init()) GOTOERROR;
	tls->isglobalinit=1;
}
if (!tls->isglobalextrainit) {
//	if (0>gnutls_global_init_extra()) GOTOERROR;
	tls->isglobalextrainit=1;
}
if (!tls->isx509alloc) {
	if (0>gnutls_certificate_allocate_credentials(&tls->x509_cred)) GOTOERROR;
	tls->isx509alloc=1;
}
if (!tls->isx509set) {
	if (cacertfilename) {
		if (0>gnutls_certificate_set_x509_trust_file(tls->x509_cred,cacertfilename,GNUTLS_X509_FMT_PEM)) GOTOERROR;
	} else {
		if (0>gnutls_certificate_set_x509_system_trust(tls->x509_cred)) GOTOERROR;
	}
	tls->isx509set=1;
}
if (certfilename && keyfilename) {
	if (0>gnutls_certificate_set_x509_key_file(tls->x509_cred,certfilename,keyfilename,GNUTLS_X509_FMT_PEM)) GOTOERROR;
}
return 0;
error:
	return -1;
}

int startsession_tls(struct tls *tls, char *hostname, int fd) {
if (tls->isserver) {
	if (0>gnutls_init(&tls->tlssession,GNUTLS_SERVER)) GOTOERROR;
} else {
	if (0>gnutls_init(&tls->tlssession,GNUTLS_CLIENT)) GOTOERROR;
}
tls->issessioninit=1;

if (tls->isverifycert) {
	if (hostname) {
		if (0>gnutls_server_name_set(tls->tlssession, GNUTLS_NAME_DNS, hostname, strlen(hostname))) GOTOERROR;
	}
}

if (0>gnutls_set_default_priority(tls->tlssession)) GOTOERROR;
if (0>gnutls_credentials_set(tls->tlssession,GNUTLS_CRD_CERTIFICATE,tls->x509_cred)) GOTOERROR;

if (tls->isverifycert) {
	if (hostname) (void)gnutls_session_set_verify_cert(tls->tlssession, hostname, 0);
	(void)gnutls_session_set_verify_cert(tls->tlssession,NULL,0); // noop
}
(void)gnutls_transport_set_int(tls->tlssession,fd);
(void)gnutls_handshake_set_timeout(tls->tlssession,GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
{ // this is copied from gnutls docs
	int ret;
	do {
		ret = gnutls_handshake(tls->tlssession);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0) {
		gnutls_certificate_type_t type;
		unsigned int status;
		gnutls_datum_t out;

		if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
						/* check certificate verification status */
						type = gnutls_certificate_type_get(tls->tlssession);
						status = gnutls_session_get_verify_cert_status(tls->tlssession);
						if (0>gnutls_certificate_verification_status_print(status, type, &out, 0)) GOTOERROR;
						if (tls->isdebug) {
							(ignore)message_log(tls->log,NORMAL_LOG,":%s:%d cert verify output: %s\n", __FILE__,__LINE__,out.data);
						}
						gnutls_free(out.data);
		}
		tls->iserror=1;
		(ignore)message_log(tls->log,NORMAL_LOG,"%s:%d TLS handshake failed: %s\n", __FILE__,__LINE__,gnutls_strerror(ret));
		GOTOERROR;
	} else {
		char *desc;
		if (tls->isdebug) {
			desc = gnutls_session_get_desc(tls->tlssession);
			(ignore)message_log(tls->log,NORMAL_LOG,"%s:%d TLS session info: %s\n", __FILE__,__LINE__,desc);
			gnutls_free(desc);
		}
	}
}
tls->isconnected=1;
tls->fd=fd;
return 0;
error:
	return -1;
}

void deinit_tls(struct tls *tls) {
if (tls->isconnected && !tls->iserror) {
	(ignore)gnutls_bye(tls->tlssession, GNUTLS_SHUT_RDWR);
}
ifclose(tls->fd);
if (tls->issessioninit) gnutls_deinit(tls->tlssession);
if (tls->isx509alloc) gnutls_certificate_free_credentials(tls->x509_cred);
// if (tls->isglobalextrainit) gnutls_global_extra_deinit();
if (tls->isglobalinit) gnutls_global_deinit();
}

void reset_tls(struct tls *tls) {
if (tls->isconnected && !tls->iserror) {
	(ignore)gnutls_bye(tls->tlssession, GNUTLS_SHUT_RDWR);
}
ifclose(tls->fd);
tls->fd=-1;
tls->isconnected=0;
tls->iserror=0;
if (tls->issessioninit) {
	gnutls_deinit(tls->tlssession);
	tls->issessioninit=0;
}
}

int timeout_readn_tls(struct tls *tls, unsigned char *buff, unsigned int n, time_t maxtime) {
gnutls_session_t s;
int fd;

s=tls->tlssession;
// fd=gnutls_transport_get_int(s);
fd=tls->fd;

if (n) while (1) {
	int r;
	r=gnutls_record_check_pending(s);
	if (!r) {
		struct pollfd pollfd;
		time_t t;
		pollfd.fd=fd;
		pollfd.events=POLLIN;
		t=time(NULL);
		if (t>=maxtime) GOTOERROR;
		switch (poll(&pollfd,1,maxtime-t)) { case 0: continue; case -1: if (errno==EINTR) continue; GOTOERROR; }

#if 0
		struct timeval tv;
		fd_set rset;
		time_t t;

		FD_ZERO(&rset);
		FD_SET(fd,&rset);
		t=time(NULL);
		if (t>=maxtime) GOTOERROR;
		tv.tv_sec=maxtime-t;
		tv.tv_usec=0;
		switch (select(fd+1,&rset,NULL,NULL,&tv)) { case 0: continue; case -1: if (errno==EINTR) continue; GOTOERROR; }
#endif
	}
	r=gnutls_record_recv(s,buff,n);
	switch (r) {
		case GNUTLS_E_REHANDSHAKE:
			if (gnutls_alert_send(s,GNUTLS_AL_WARNING,GNUTLS_A_NO_RENEGOTIATION)) GOTOERROR; // no break
		case GNUTLS_E_AGAIN:
		case GNUTLS_E_INTERRUPTED:
			continue;
	}
	if (r<0) {
		if (tls->isdebug) {
			(ignore)message_log(tls->log,NORMAL_LOG,"%s:%d TLS error in recv: %s\n", __FILE__,__LINE__,gnutls_strerror(r));
		}
		GOTOERROR;
	}
	n-=r;
	if (!n) break;
	buff+=r;
}
return 0;
error:
	return -1;
}

int timeout_writen_tls(struct tls *tls, unsigned char *buff, unsigned int n, time_t maxtime) {
gnutls_session_t s;
int fd;

s=tls->tlssession;
// fd=gnutls_transport_get_int(s);
fd=tls->fd;

if (n) while (1) {
	int r;
	struct pollfd pollfd;
	time_t t;
	pollfd.fd=fd;
	pollfd.events=POLLOUT;
	t=time(NULL);
	if (t>=maxtime) GOTOERROR;
	switch (poll(&pollfd,1,maxtime-t)) { case 0: continue; case -1: if (errno==EINTR) continue; GOTOERROR; }
#if 0
	struct timeval tv;
	fd_set wset;
	time_t t;

	FD_ZERO(&wset);
	FD_SET(fd,&wset);
	t=time(NULL);
	if (t>=maxtime) GOTOERROR;
	tv.tv_sec=maxtime-t;
	tv.tv_usec=0;
	switch (select(fd+1,NULL,&wset,NULL,&tv)) { case 0: continue; case -1: if (errno==EINTR) continue; GOTOERROR; }
#endif

	r=gnutls_record_send(s,buff,n);
	switch (r) {
		case GNUTLS_E_AGAIN:
		case GNUTLS_E_INTERRUPTED:
			continue;
	}
	if (r<0) {
		if (tls->isdebug) {
			(ignore)message_log(tls->log,NORMAL_LOG,"%s:%d TLS error in send: %s\n", __FILE__,__LINE__,gnutls_strerror(r));
		}
		GOTOERROR;
	}
	n-=r;
	if (!n) break;
	buff+=r;
}
return 0;
error:
	return -1;
}

