#include "icmp_request.h"

void send_v4_icmp_request(struct icmp_request *ir)
{
	int len;
	struct icmp *icmp;
	static int seq = 1;

	icmp = (struct icmp*) ir->buf;
	icmp->icmp_type = ir->request_type;
	icmp->icmp_code = 0;
	icmp->icmp_id = ir->id;
	icmp->icmp_seq = seq++;
	memset(icmp->icmp_data, 0xa5, DATA_LEN);
	Gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	len = 8 + DATA_LEN;  /* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short*) icmp, len);

	Sendto(ir->sockfd, ir->buf, len, 0, ir->sasend, ir->salen);
}

void send_v6_icmp_request(struct icmp_request *ir)
{
#ifdef	IPV6
	int					len;
	struct icmp6_hdr	*icmp6;
	static int seq = 1;

	icmp6 = (struct icmp6_hdr *) ir->buf;
	icmp6->icmp6_type = ir->request_type;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id = ir->id;
	icmp6->icmp6_seq = seq++;
	memset((icmp6 + 1), 0xa5, DATA_LEN);	 /* fill with pattern */
	Gettimeofday((struct timeval *) (icmp6 + 1), NULL);

	len = 8 + DATA_LEN;		/* 8-byte ICMPv6 header */

	Sendto(ir->sockfd, ir->buf, len, 0, ir->sasend, ir->salen);
	/* 4kernel calculates and stores checksum for us */	
#endif	
}

