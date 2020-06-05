#include "icmp_request.h"

int	datalen = 56;		/* data that goes with ICMP echo request */

int main(int argc, char **argv)
{
	struct addrinfo	*ai;
	char *h;
	int datalen  = 56;
	struct icmp_request ir;

	if (argc < 3) {
		printf("usage: hostname icmp_request_type\n");
		printf("1 -- ICMP_TIMESTAMP \n"
			   "2 -- ICMP_TIME_EXCEEDED \n");
		exit(-1);
	}

	memset(&ir, 0, sizeof(ir));
	
	if (atoi(argv[2]) == 1) {
		ir.request_type = ICMP_TIMESTAMP;
		ir.reply_type = ICMP_TIMESTAMPREPLY;
		ir.fhandle_data = handle_timestamp_reply_data;
	} else if (atoi(argv[2]) == 2) {
		ir.request_type = ICMP_TIME_EXCEEDED;
		ir.reply_type = ICMP_TIME_EXCEEDED;  /* what the reply type */
	} else {
		printf("bad icmp request type\n");
		exit(-1);
	}

	ai = Host_serv(argv[1], NULL, 0, 0);
	h = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
	printf("Hostname %s (%s): %d data bytes\n",
			ai->ai_canonname ? ai->ai_canonname : h,
			h, datalen);

	ir.sasend = ai->ai_addr;
	ir.sarecv = Calloc(1, ai->ai_addrlen);
	ir.salen = ai->ai_addrlen;

	ir.id = getpid() & 0xffff;

	if (ai->ai_family == AF_INET) {
		ir.sockfd = Socket(ai->ai_addr->sa_family, SOCK_RAW, IPPROTO_ICMP);
		ir.fsend = send_v4_icmp_request;
		ir.fproc = read_v4_icmp_reply;
#ifdef	IPV6
	} else if (ai->ai_family == AF_INET6) {
		ir.sockfd = Socket(ai->ai_addr->sa_family, SOCK_RAW, IPPROTO_ICMPV6);
		ir.fsend = send_v6_icmp_request;
		ir.fproc = read_v6_icmp_reply;
		if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)
								 ai->ai_addr)->sin6_addr)))
			err_quit("cannot request IPv4-mapped IPv6 address");
#endif
	} else
		err_quit("unknown address family %d", ai->ai_family);

	ir.fsend(&ir);
	
	read_reply(&ir);

	close(ir.sockfd);

	return 0;
}
