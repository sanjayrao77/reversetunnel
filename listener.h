
struct oneipv4_listener {
	uint32_t ipv4;
	struct oneipv4_listener *next;
};

struct listener {
	struct {
		int tunnel; // listen socket
		int client; // listen socket
		int tcp_tunnel;
		int tcp_client;
	} sockets;
	struct {
		struct {
			struct oneipv4_listener *first;
		} tunnel;
		struct {
			struct oneipv4_listener *first;
		} client;
	} authorized;
	struct {
		struct oneipv4_listener *first_oneipv4;
	} recycle;
	struct blockmem blockmem;
	unsigned char password8[8];
};

void clear_listener(struct listener *f);
void deinit_listener(struct listener *f);
int init_listener(struct listener *f, int tunnelport, uint32_t tunneladdress, int clientport, uint32_t clientaddress,
		unsigned char *password8);
int waitfortunnel_listener(struct listener *f);
int waitforclient_listener(struct listener *f);
void closeclients_listener(struct listener *f);
int proxyclients_listener(struct listener *f);
int add_tunnel_authorized_listener(struct listener *f, uint32_t ipv4);
int add_client_authorized_listener(struct listener *f, uint32_t ipv4);
