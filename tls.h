
struct tls {
	int isglobalinit;
	int isglobalextrainit;
	int isx509alloc;
	int isx509set;
	int issessioninit;
	int isverifycert;
	int iserror;
	int isdebug;
	int isconnected;
	int isserver;
	int fd;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t	tlssession;
	struct log *log;
};
H_CLEARFUNC(tls);
int init_tls(struct tls *tls, struct log *log, char *cacertfilename, char *keyfilename, char *certfilename, int isserver);
void deinit_tls(struct tls *tls);
void reset_tls(struct tls *tls);
int startsession_tls(struct tls *tls, char *hostname, int fd);
int timeout_readn_tls(struct tls *tls, unsigned char *buff, unsigned int n, time_t maxtime);
int timeout_writen_tls(struct tls *tls, unsigned char *buff, unsigned int n, time_t maxtime);
