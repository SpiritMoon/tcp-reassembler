#ifndef _MYTCP_H_
#define _MYTCP_H_

#include "mytypes.h"
#include "myip.h"

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

#define TH_OFF(th)  (is_little_endian() ? (th)->th_off : (th)->th_x2)

#define get_tcp_header_p(pcap_packet) get_tcp_header(get_ip_header(pcap_packet))
#define get_tcp_header_n(node) get_tcp_header_p(((pcap_item *)node->data)->packet)

// return beginning memory address of tcp data
#define get_tcp_data(tcp_header) (tByte *)((tString)(tcp_header) + TH_OFF(tcp_header) * 4)
#define get_tcp_data_n(node) (tByte *)((tString)(get_tcp_header_n(node)) + TH_OFF(get_tcp_header_n(node)) * 4)

#define get_tcp_data_length_p(pcap_packet) get_tcp_data_length(get_ip_header(pcap_packet))
#define get_tcp_data_length_n(node) get_tcp_data_length_p(((pcap_item *)node->data)->packet)

#define is_tcp_syn(tcp_header) (tcp_header->th_flags & TH_SYN)
#define is_tcp_fin(tcp_header) (tcp_header->th_flags & TH_FIN)


tcp_hdr *get_tcp_header(tVar ip_header);
size_t get_tcp_data_length(tVar ip_header);

#endif /* _MYTCP_H_ */
