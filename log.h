
struct log {
	int issyslog;
	unsigned int level_bitmask;
	FILE *fout;
	struct {
		FILE *f;
	} tofree;
};
H_CLEARFUNC(log);

#define NORMAL_LOG (1<<1)
#define VERBOSE_LOG	(1<<2)
#define ALL_LOG	(~0)

#define init_log(a,b,c,d) reinit_log(a,b,c,d)
int reinit_log(struct log *log, FILE *fout, int issyslog, unsigned int levels);
void deinit_log(struct log *log);
int message_log(struct log *log, unsigned int level, const char *fmt, ...);
