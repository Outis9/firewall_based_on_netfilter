#define SOC_MIN	    0x6000
#define BANICMP     0x6001
#define BANIP       0x6002
#define BANPORT     0x6003
#define NOWRULE     0x6004
#define BANTCP		0x6005
#define BANUDP		0x6006
#define FLUSH		0x6007
#define SOC_MAX		0x6100

#define MAX 1000

typedef struct ban_status{
	int tcp_status;
	int udp_status;
	int icmp_status;
	int dest_ip_status;
	int source_ip_status;
	int source_port_status;
	int dest_port_status;

	unsigned int ban_ip;
	unsigned short ban_port;
	unsigned int ban_source_ip_list[MAX + 1];
	unsigned short ban_source_port_list[MAX + 1];
	unsigned int ban_dest_ip_list[MAX + 1];
	unsigned short ban_dest_port_list[MAX + 1];
}ban_status;