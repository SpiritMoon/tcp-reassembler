#ifndef _NETINET_UDP_H_
#define _NETINET_UDP_H_

#include "tcpdump_stdinc.h"

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
	u_int16_t	uh_sport;		/* source port */
	u_int16_t	uh_dport;		/* destination port */
	u_int16_t	uh_ulen;		/* udp length */
	u_int16_t	uh_sum;			/* udp checksum */
};

#endif /* _NETINET_UDP_H_ */
