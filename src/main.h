#ifndef MY_MAIN_H
#define MY_MAIN_H

#include <pcap.h>
#include "types.h"

// use 0D0A0D0A0D0A as delimiter
#define REQUEST_GAP_LEN    6
#define REQUEST_GAP        "\r\n\r\n\r\n"

#define PCAP_DIR           "pcaps"
#define REQS_DIR           "reqts"
#define HTTP_DIR           "files"

tCString pcap_path;
tCString reqs_path;
tCString http_path;

typedef struct {
    struct pcap_pkthdr header;
    tByte *packet;
} pcap_item;


#define get_ip_header_n(node) get_ip_header(((pcap_item *)node->data)->packet)
#define get_ip_id_n(node) get_ip_id(get_ip_header_n(node))

#define get_tcp_header_p(pcap_packet) get_tcp_header(get_ip_header(pcap_packet))
#define get_tcp_header_n(node) get_tcp_header_p(((pcap_item *)node->data)->packet)
// return beginning memory address of tcp data
#define get_tcp_data_n(node) (tByte *)((tString)(get_tcp_header_n(node)) + th_off(get_tcp_header_n(node)) * 4)
#define get_tcp_data_length_p(pcap_packet) get_tcp_data_length(get_ip_header(pcap_packet))
#define get_tcp_data_length_n(node) get_tcp_data_length_p(((pcap_item *)node->data)->packet)

#endif /* MY_MAIN_H */
