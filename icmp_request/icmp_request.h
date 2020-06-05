#include	"unp.h"
#include	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>

#define	BUFSIZE		1500
#define DATA_LEN    56

struct icmp_request;

void     send_v4_icmp_request(struct icmp_request *);
void     send_v6_icmp_request(struct icmp_request *);
void 	 read_v4_icmp_reply(char *ptr, ssize_t len, struct msghdr *msg, struct icmp_request *ir);
void     read_v6_icmp_reply(char *ptr, ssize_t len, struct msghdr *msg, struct icmp_request *ir);
void     handle_timestamp_reply_data(u_int8_t * data);

void read_reply(struct icmp_request *ir);

struct icmp_request {
	void (*fproc)(char *ptr, ssize_t len, struct msghdr *msg, struct icmp_request *);
	void (*fsend)(struct icmp_request *);
	void (*finit)(struct icmp_request *);
	void (*fhandle_data)(u_int8_t *data);
	struct sockaddr *sasend;
	struct sockaddr *sarecv;
	socklen_t salen;
	int request_type;
	int reply_type;
	int sockfd;
	int id;
	char buf[BUFSIZE];	
};


#ifdef	IPV6

#include	<netinet/ip6.h>
#include	<netinet/icmp6.h>

#endif
