#ifndef MY_TCP_H
#define MY_TCP_H

#include "ip.h"

typedef u_int32_t tcp_seq;

typedef struct {
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    tcp_seq th_seq;         /* sequence number */
    tcp_seq th_ack;         /* acknowledgement number */
// #if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;       /* (unused) */
    u_int8_t th_off:4;      /* data offset */
    u_int8_t th_flags;
#define TH_FIN    0x01
#define TH_SYN    0x02
#define TH_RST    0x04
#define TH_PUSH   0x08
#define TH_ACK    0x10
#define TH_URG    0x20
    u_int16_t th_win;       /* window */
    u_int16_t th_sum;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */
} tcp_hdr;

#define th_off(th)  (is_little_endian() ? (th)->th_off : (th)->th_x2)

extern tcp_hdr *get_tcp_header(tByte *ip_header);
extern size_t get_tcp_data_length(tByte *ip_header);
extern tByte *get_tcp_data(tcp_hdr *tcp_header);
extern tBool is_tcp_syn(tcp_hdr *tcp_header);
extern tBool is_tcp_fin(tcp_hdr *tcp_header);

#endif /* MY_TCP_H */
