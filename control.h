
#define TERMINATOR_TYPE_CMD_CONTROL	0
#define ONEIP_TYPE_CMD_CONTROL	1
#define ONETUNNEL_TYPE_CMD_CONTROL	2
#define LIST_AUTHORIZED_TUNNEL_TYPE_CMD_CONTROL	3
#define LIST_AUTHORIZED_CLIENT_TYPE_CMD_CONTROL	4
#define LIST_TUNNELS_TYPE_CMD_CONTROL 5
#define LASTIP_TUNNEL_TYPE_CMD_CONTROL	6
#define LASTIP_CLIENT_TYPE_CMD_CONTROL	7
#define ADDIP_TUNNEL_TYPE_CMD_CONTROL	8
#define ADDIP_CLIENT_TYPE_CMD_CONTROL	9

struct cmd_control {
	int type;
	union {
		struct oneip_cmd_control {
			uint32_t ipv4;
		} oneip;
		struct onetunnel_cmd_control {
			pid_t pid;
			uint64_t timestamp;
			uint32_t ipv4;
			unsigned char hostname8[8];
			unsigned short port;
		} onetunnel;
	};
};

