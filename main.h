#ifndef _MAIN_H_
#define _MAIN_H_


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
// # include <netinet/ip.h>
// # include <netinet/ip6.h>
// # include <netinet/tcp.h>
// # include <netinet/udp.h>
// # include <arpa/inet.h>
#include "mytypes.h"
#include "mynetwork.h"
#include "myip.h"
#include "mytcp.h"
#include "myudp.h"
#endif /* _WIN32 */

#include <pcap.h>

// constant
// use 0D0A0D0A0D0A as delimiter
#define REQUEST_GAP_LEN    6
#define REQUEST_GAP        "\r\n\r\n\r\n"

// directory
#define REPORT_DIR         "report"
#define PCAP_DIR           "pcaps"
#define REQS_DIR           "requests"
#define HTTP_DIR           "files"

#define HASH_SIZE          4000
// function

typedef struct {
    struct pcap_pkthdr header;
    byte *packet;
} pcap_item;


#endif /* _MAIN_H_ */
