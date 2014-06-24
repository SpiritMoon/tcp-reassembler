#ifndef MY_NETWORK_H
#define MY_NETWORK_H

#include "types.h"

#undef CHUNK
#define CHUNK 16384
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
typedef uint32_t in_addr_t;
struct in_addr {
    in_addr_t s_addr;
};

struct in6_addr {
    union
      {
    uint8_t __u6_addr8[16];
    uint16_t __u6_addr16[8];
    uint32_t __u6_addr32[4];
      } __in6_u;
#define s6_addr        __in6_u.__u6_addr8
#define s6_addr16      __in6_u.__u6_addr16
#define s6_addr32      __in6_u.__u6_addr32
};

#define AF_INET     2
#define AF_INET6    10

extern tBool is_little_endian();
#undef htonl
extern uint32_t htonl(uint32_t hostlong);
#undef htons
extern uint16_t htons(uint16_t hostshort);
#undef ntohl
extern uint32_t ntohl(uint32_t netlong);
#undef ntohs
extern uint16_t ntohs(uint16_t netshort);
extern const char *inet_ntop(int af, const void *src, char *dst, size_t size);

#endif /* MY_NETWORK_H */
