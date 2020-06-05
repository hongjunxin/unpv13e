#include "icmp_request.h"

void read_reply(struct icmp_request *ir)
{
	int				size;
	char			recvbuf[BUFSIZE];
	char			controlbuf[BUFSIZE];
	struct msghdr	msg;
	struct iovec	iov;
	ssize_t			n;

	if (ir->finit)
		ir->finit(ir);

	size = 60 * 1024;		/* OK if setsockopt fails */
	setsockopt(ir->sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = ir->sarecv;
	msg.msg_namelen = ir->salen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;
	msg.msg_controllen = sizeof(controlbuf);
	
	n = recvmsg(ir->sockfd, &msg, 0);
	if (n < 0)
		err_sys("recvmsg error");
	
	ir->fproc(recvbuf, n, &msg, ir);
}

void handle_timestamp_reply_data(u_int8_t *data)
{
	unsigned int *t;
	struct tm tm;
	struct timeval tv;
	char date[64] = {'\0'};
	
	t = (unsigned int*) data;
	tv.tv_sec = *t;
	
    strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", localtime_r(&tv.tv_sec, &tm));
    printf("originate timestamp: %u, %s\n", *t, date);
}

void read_v4_icmp_reply(char *ptr, ssize_t len, struct msghdr *msg, struct icmp_request *ir)
{
	int				hlen1, icmplen;
	struct ip		*ip;
	struct icmp		*icmp;	

	ip = (struct ip *) ptr;
	hlen1 = ip->ip_hl << 2;		/* length of IP header */
	if (ip->ip_p != IPPROTO_ICMP)
		return;

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8)
		return;				/* malformed packet */

	if (icmp->icmp_type == ir->reply_type) {
		if (icmp->icmp_id != ir->id) {
			printf("[reply] icmp_id wrong, icmp->icmp_id=%d, ir->id=%d\n", 
				icmp->icmp_id, ir->id);
			return;
		}	
		if (icmplen < 16) {
			printf("[reply] no icmp data to used\n");
			return;
		}	

		printf("%d bytes from %s: seq=%u\n",
				icmplen, Sock_ntop_host(ir->sarecv, ir->salen), icmp->icmp_seq);

		if (ir->fhandle_data)
			ir->fhandle_data(icmp->icmp_data);
	} else {
		printf("%d bytes from %s: type = %d, code = %d (icmp type wrong)\n",
				icmplen, Sock_ntop_host(ir->sarecv, ir->salen),
				icmp->icmp_type, icmp->icmp_code);
	}
}

void read_v6_icmp_reply(char *ptr, ssize_t len, struct msghdr *msg, struct icmp_request *ir)
{
#ifdef	IPV6
	struct icmp6_hdr	*icmp6;
	struct cmsghdr		*cmsg;
	int					hlim;

	icmp6 = (struct icmp6_hdr *) ptr;
	if (len < 8)
		return;  /* malformed packet */

	if (icmp6->icmp6_type == ir->reply_type) {
		if (icmp6->icmp6_id != ir->id) {
			printf("[reply] icmp6_id wrong, icmp6->icmp6_id=%d, ir->id=%d\n", 
				icmp6->icmp6_id, ir->id);
			return;
		}
		if (len < 16) {
			printf("[reply] no icmp data to used\n");
			return;
		}
		
		hlim = -1;
		for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IPV6 &&
				cmsg->cmsg_type == IPV6_HOPLIMIT) {
				hlim = *(u_int32_t *)CMSG_DATA(cmsg);
				break;
			}
		}
		printf("%d bytes from %s: seq=%u, hlim=",
				(int) len, Sock_ntop_host(ir->sarecv, ir->salen), icmp6->icmp6_seq);		
		
		if (hlim == -1)
			printf("???\n");	/* ancillary data missing */
		else
			printf("%d\n", hlim);

		if (ir->fhandle_data)
			ir->fhandle_data((u_int8_t *) (icmp6 + 1));
	} else {
		printf("%d bytes from %s: type = %d, code = %d (icmp type wrong)\n",
				(int) len, Sock_ntop_host(ir->sarecv, ir->salen),
				icmp6->icmp6_type, icmp6->icmp6_code);
	}
#endif	/* IPV6 */
}


