#include <errno.h>
#include "mynetwork.h"

tBool is_little_endian()
{
    unsigned int i = 1;
    return *(char *)&i;
}

// network order to be big endian
uint32_t htonl(uint32_t host32)
{
    if (!is_little_endian())
        return host32;
    return ((host32 & 0x000000ff) << 24)
         | ((host32 & 0x0000ff00) << 8)
         | ((host32 & 0x00ff0000) >> 8)
         | ((host32 & 0xff000000) >> 24);
}

uint16_t htons(uint16_t host16)
{
    if (!is_little_endian())
        return host16;
    return ((host16 & 0xff) << 8) | ((host16 & 0xff00) >> 8);
}

uint32_t ntohl(uint32_t net32)
{
    return htonl(net32);
}

uint16_t ntohs(uint16_t net16)
{
    return htons(net16);
}
