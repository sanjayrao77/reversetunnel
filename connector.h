struct connector {
	struct tls tls;
	struct {
//		int tunnel; // this is replaced with tls
		int server;
	} sockets;
	struct {
		struct {
			uint32_t ipv4;
			unsigned short port;
		} tunnel;
		struct {
			uint32_t ipv4;
			unsigned short port;
		} server;
	} config;
	unsigned char password8[8];
	unsigned char hostname8[8];
	struct log *log;
};

void clear_connector(struct connector *c);
void deinit_connector(struct connector *c);
int init_connector(struct connector *c, struct log *log, uint32_t ipv4_tunnel, unsigned short port_tunnel,
		uint32_t ipv4_server, unsigned short port_server, unsigned char *password8, unsigned char *hostname8);
int connecttunnel_connector(struct connector *c);
int connectserver_connector(struct connector *c);
int proxyclients_connector(struct connector *c);
void reset_connector(struct connector *c);
int waitforclient_connector(struct connector *c);
