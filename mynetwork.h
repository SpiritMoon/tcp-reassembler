#ifndef _MYNETWORK_H_
#define _MYNETWORK_H_

#include "mytypes.h"

// the type code of the pcap_packet in an ETHERNET header
#define ETHER_TYPE_IP4     0x0800
#define ETHER_TYPE_IP6     0x86DD
#define ETHER_TYPE_8021Q   0x8100
// the offset value of the pcap_packet (in byte number)
#define ETHER_OFFSET_IP4   14
#define ETHER_OFFSET_IP6   14
#define ETHER_OFFSET_8021Q 18
// protocol code
#define PROTOCOL_IP4       AF_INET
#define PROTOCOL_IP6       AF_INET6
#define PROTOCOL_TCP       0x06
#define PROTOCOL_UDP       0x11

#define INET_ADDRSTRLEN    16
#define INET6_ADDRSTRLEN   46

#ifndef _SOCKLEN_T
#define _SOCKLEN_T
typedef unsigned int socklen_t;
#endif /* _SOCKLEN_T */

tBool is_little_endian();
#undef htonl
uint32_t htonl(uint32_t hostlong);
#undef htons
uint16_t htons(uint16_t hostshort);
#undef ntohl
uint32_t ntohl(uint32_t netlong);
#undef ntohs
uint16_t ntohs(uint16_t netshort);

#endif /* _MYNETWORK_H_ */
