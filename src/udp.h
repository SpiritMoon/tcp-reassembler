#ifndef MY_UDP_H
#define MY_UDP_H

#include "ip.h"

typedef struct {
    u_int16_t uh_sport;       /* source port */
    u_int16_t uh_dport;       /* destination port */
    u_int16_t uh_ulen;        /* udp length */
    u_int16_t uh_sum;         /* udp checksum */
} udp_hdr;

#endif /* MY_UDP_H */
