
int timeout_readn(int fd, unsigned char *msg, unsigned int len, time_t timeout);
int timeout_writen(int fd, unsigned char *msg, unsigned int len, time_t timeout);
int getuid_misc(uid_t *uid_out, char *user);
unsigned int slowtou(char *str);
void hexdecode(unsigned char *dest, unsigned int len, char *src);
