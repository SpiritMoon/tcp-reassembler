#ifndef _MYUDP_H_
#define _MYUDP_H_

#include "mytypes.h"

typedef struct {
    u_int16_t uh_sport;       /* source port */
    u_int16_t uh_dport;       /* destination port */
    u_int16_t uh_ulen;        /* udp length */
    u_int16_t uh_sum;         /* udp checksum */
} udp_hdr;

#endif /* _MYUDP_H_ */
