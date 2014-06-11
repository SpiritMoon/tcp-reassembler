#ifndef _MAIN_H_INCLUDE_
#define _MAIN_H_INCLUDE_


#ifdef _WIN32
# include <Winsock2.h>
# include <Ws2tcpip.h>
# include "Win32/tcpdump-stdinc.h"
# include "Win32/ip.h"
# include "Win32/ip6.h"
# include "Win32/tcp.h"
# include "Win32/udp.h"
# include "Win32/dirent.h"
#else
# include <dirent.h>
# include <netinet/ip.h>
# include <netinet/ip6.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <arpa/inet.h>
# include <sys/stat.h>

# define TH_OFF(th)  ((th)->th_off)

#endif /* _WIN32 */

#include <pcap.h>

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
// constant
// use 0D0A0D0A0D0A as delimiter
#define REQUEST_GAP_LEN    6
#define REQUEST_GAP        "\r\n\r\n\r\n"

#define PCAP_DIR           "pcaps"
#define REQS_DIR           "requests"
#define HTTP_DIR           "files"

#define HASH_SIZE          4000
// function
#define _IP4(x) ((ip4_hdr *)(x))
#define _IP6(x) ((ip6_hdr *)(x))


typedef struct ip ip4_hdr;
typedef struct ip6_hdr ip6_hdr;
typedef struct tcphdr tcp_hdr;
typedef struct {
    struct pcap_pkthdr header;
    byte *packet;
} pcap_item;


int get_ip_protocol(void *ip_packet);
tcp_hdr *get_tcp_header(void *ip_packet);

#endif /* _MAIN_H_INCLUDE_ */
