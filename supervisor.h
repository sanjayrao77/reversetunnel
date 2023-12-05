
struct entry_supervisor {
	int isactive; // this is set in supervisor, not in fork
	pid_t pid; // ditto
	uint64_t timestamp; // ditto
	uint32_t ipv4; // ditto
	unsigned char hostname8[8];
	unsigned short port;
};

struct common_supervisor {
	int isinit;
	pthread_mutex_t mainlock;
	struct {
		uint32_t ipv4_lastblocked;
	} client;
};

struct oneipv4_supervisor {
	uint32_t ipv4;
	struct oneipv4_supervisor *next;
};

struct supervisor {
	int isquit;
	struct tls tls;
	struct {
		int unix_control;
		int tunnel;
	} sockets;
	struct {
		unsigned short port; // for tunnel
		unsigned char password8[8];
		uint32_t ifaddr_client;
		int isdenyall_tunnel;
		int isdenyall_client;
	} config;
	struct {
		struct common_supervisor *common;
		unsigned int max;
		unsigned int numactive; // have to walk it
		struct entry_supervisor *entries;
	} shared;
	struct {
		struct {
			struct oneipv4_supervisor *first;
			uint32_t ipv4_lastblocked;
		} tunnel;
		struct {
			struct oneipv4_supervisor *first;
		} client;
	} authorized;
	struct {
		struct oneipv4_supervisor *first_oneipv4;
	} recycle;
	struct {
		void *mmap;
		unsigned int mmaplength;
	} tofree;
	struct blockmem blockmem;
	struct log *log;
};

void clear_supervisor(struct supervisor *s);
void deinit_supervisor(struct supervisor *s);
int init_supervisor(struct supervisor *s, struct log *log, unsigned int maxentries, uint32_t ifaddr_tunnel, unsigned short port_tunnel,
		uint32_t ifaddr_client, unsigned char *password8, char *keyfile, char *certfile);
int addcontrol_supervisor(struct supervisor *s, char *path);
int add_tunnel_authorized_supervisor(struct supervisor *f, uint32_t ipv4);
int add_client_authorized_supervisor(struct supervisor *f, uint32_t ipv4);
int step_supervisor(struct supervisor *s);
