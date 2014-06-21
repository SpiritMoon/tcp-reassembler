#include "mytcp.h"

/*
 * @ip_header: beginning memory address of IP packet, same with IP header
 */
tcp_hdr *get_tcp_header(tVar ip_header)
{
    tcp_hdr *tcp_header = NULL;
    int protocol = get_ip_protocol(ip_header);
    if (is_ip4(protocol))
        tcp_header = (tcp_hdr *)((char *)(ip_header) + IP4(ip_header)->ip_hl * 4);
    else if (is_ip6(protocol))
        // 40 is IPv6 header length
        tcp_header = (tcp_hdr *)((char *)(ip_header) + 40);
    return tcp_header;
}

size_t get_tcp_data_length(tVar ip_header)
{
    size_t ip_len = 0;
    size_t ip_header_len = 0;
    size_t tcp_header_len = 0;
    int protocol = get_ip_protocol(ip_header);

    if (is_ip4(protocol))
    {
        ip_header_len = IP4(ip_header)->ip_hl * 4;
        ip_len = ntohs(IP4(ip_header)->ip_len);
    }
    else
    {
        ip_len = ntohs(IP6(ip_header)->ip6_plen);
    }
    // `TH_OFF` specifies the size of the TCP header in 32-bit words
    tcp_header_len = TH_OFF(get_tcp_header(ip_header)) * 4;

    return ip_len - (ip_header_len + tcp_header_len);
}
