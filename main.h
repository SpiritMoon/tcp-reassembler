#ifndef _MAIN_H_
#define _MAIN_H_


#include <pcap.h>

// constant
// use 0D0A0D0A0D0A as delimiter
#define REQUEST_GAP_LEN    6
#define REQUEST_GAP        "\r\n\r\n\r\n"

#define REPORT_DIR         "report"
#define PCAP_DIR           "pcaps"
#define REQS_DIR           "requests"
#define HTTP_DIR           "files"

#define HASH_SIZE          4000

typedef struct {
    struct pcap_pkthdr header;
    byte *packet;
} pcap_item;


#endif /* _MAIN_H_ */
