#ifndef _MYIP_H_
#define _MYIP_H_

#include "mytypes.h"
#include "mynetwork.h"
#include "util.h"

#define IP_PORT_FORMAT     "%s.%d-%s.%d"

#define AF_INET     2
#define AF_INET6    10

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

typedef struct {
// #if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;           /* header length */
    unsigned int ip_v:4;            /* version */
    u_int8_t ip_tos;                /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                /* reserved fragment flag */
#define IP_DF 0x4000                /* dont fragment flag */
#define IP_MF 0x2000                /* more fragments flag */
#define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    u_int8_t ip_ttl;                /* time to live */
    u_int8_t ip_p;                  /* protocol */
    u_short ip_sum;                 /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
} ip4_hdr;

typedef struct {
    union
      {
    struct ip6_hdrctl
      {
        uint32_t ip6_un1_flow;      /* 4 bits version, 8 bits TC, 20 bits flow-ID */
        uint16_t ip6_un1_plen;      /* payload length */
        uint8_t  ip6_un1_nxt;       /* next header */
        uint8_t  ip6_un1_hlim;      /* hop limit */
      } ip6_un1;
    uint8_t ip6_un2_vfc;            /* 4 bits version, top 4 bits tclass */
      } ip6_ctlun;
    struct in6_addr ip6_src;        /* source address */
    struct in6_addr ip6_dst;        /* destination address */
} ip6_hdr;

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim


#define IP4(x) ((ip4_hdr *)(x))
#define IP6(x) ((ip6_hdr *)(x))
#define IP4_V(x) (is_little_endian() ? (x)->ip_v : (x)->ip_hl)
#define IP4_HL(x) (is_little_endian() ? (x)->ip_hl : (x)->ip_v)

#define SPORT(upper_layer) (*(unsigned short *)(upper_layer))
#define DPORT(upper_layer) (*(unsigned short *)((upper_layer) + 2))

#define is_ip4(protocol) (protocol == PROTOCOL_IP4)
#define is_ip6(protocol) (protocol == PROTOCOL_IP6)
#define is_ip(protocol) (is_ip4(protocol) || is_ip6(protocol))

#define get_ip_header_n(node) get_ip_header(((pcap_item *)node->data)->packet)
#define get_ip_id_n(node) get_ip_id(get_ip_header_n(node))

tVar get_ip_header(tByte *pcap_packet);
int get_ip_protocol(tVar ip_header);
unsigned short get_ip_id(tVar ip_header);
tBool is_tcp(tVar ip_header);
tBool is_udp(tVar ip_header);
tByte *get_transport_layer_header(tVar ip_header);
tCString get_ip_port_pair(tVar ip_header);
tCString reverse_ip_port_pair(tCString ip_port_pair);
tBool is_same_ip_port(tVar ip_header1, tVar ip_header2);
tCString get_ip_pair_from_filename(tCString filename);

#endif /* _MYIP_H_ */
