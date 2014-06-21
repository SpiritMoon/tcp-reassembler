#include "myip.h"

/*
 * @protocol: IPv4 or IPv6
 */
tVar get_ip_header(tByte *pcap_packet)
{
    int offset;
    int ether_type = ((int)pcap_packet[12] << 8) | (int)pcap_packet[13];
    switch (ether_type) {
        case ETHER_TYPE_8021Q:
            offset = ETHER_OFFSET_8021Q;
            break;
        case ETHER_TYPE_IP4:
            offset = ETHER_OFFSET_IP4;
            break;
        case ETHER_TYPE_IP6:
            offset = ETHER_OFFSET_IP6;
            break;
        default:
            return NULL;
    }
    //skip past the Ethernet II header
    return (tVar)(pcap_packet + offset);
}

int get_ip_protocol(tVar ip_header)
{
    char version = *((char *)ip_header);
    version = is_little_endian() ? ((version & 0xF0) >> 4) : (version & 0x0F);
    return 4 == version ? PROTOCOL_IP4 : PROTOCOL_IP6;
}

unsigned short get_ip_id(tVar ip_header)
{
    int protocol = get_ip_protocol(ip_header);
    return is_ip4(protocol) ? ntohs(IP4(ip_header)->ip_id) : 0;
}

tBool is_tcp(tVar ip_header)
{
    int protocol = get_ip_protocol(ip_header);
    if (is_ip4(protocol))
        return IP4(ip_header)->ip_p == PROTOCOL_TCP;
    if (is_ip6(protocol))
        return IP6(ip_header)->ip6_nxt == PROTOCOL_TCP;
    return FALSE;
}

tBool is_udp(tVar ip_header)
{
    int protocol = get_ip_protocol(ip_header);
    if (is_ip4(protocol))
        return IP4(ip_header)->ip_p == PROTOCOL_UDP;
    if (is_ip6(protocol))
        return IP6(ip_header)->ip6_nxt == PROTOCOL_UDP;
    return FALSE;
}

// transport layer
tByte *get_transport_layer_header(tVar ip_header)
{
    int protocol = get_ip_protocol(ip_header);
    tByte *upper_layer = (tByte *)(ip_header);
    // 40 is IPv6 header length
    upper_layer += is_ip4(protocol) ? IP4(ip_header)->ip_hl * 4 : 40;
    return upper_layer;
}

/*
 * return something like "192.168.137.1.80--192.168.137.233.8888"
 */
tCString get_ip_port_pair(tVar ip_header)
{
    int addr_str_len;
    tVar ip_src;
    tVar ip_dst;
    int protocol = get_ip_protocol(ip_header);

    if (is_ip4(protocol))
    {
        addr_str_len = INET_ADDRSTRLEN;
        ip_src = &IP4(ip_header)->ip_src;
        ip_dst = &IP4(ip_header)->ip_dst;
    }
    else
    {
        addr_str_len = INET6_ADDRSTRLEN;
        ip_src = &IP6(ip_header)->ip6_src;
        ip_dst = &IP6(ip_header)->ip6_dst;
    }

    char buf_src[INET6_ADDRSTRLEN];
    char buf_dst[INET6_ADDRSTRLEN];
    inet_ntop(protocol, ip_src, buf_src, addr_str_len);
    inet_ntop(protocol, ip_dst, buf_dst, addr_str_len);

    tByte *upper_layer = get_transport_layer_header(ip_header);
    int port_src = ntohs(SPORT(upper_layer));
    int port_dst = ntohs(DPORT(upper_layer));

    // max port number in string takes 5 bytes
    tString str = mymalloc((addr_str_len + 5) * 2 + 5);
    sprintf(str, IP_PORT_FORMAT, buf_src, port_src, buf_dst, port_dst);
    // replace all ':' to '.' in IPv6
    for (int i = 0; * (str + i); i++)
        if (*(str + i) == ':')
            *(str + i) = '.';

    return (tCString)str;
}

tCString reverse_ip_port_pair(tCString ip_port_pair)
{
    tString pair2 = strstr(ip_port_pair, "-");
    tString pair1 = strndup(ip_port_pair, pair2 - ip_port_pair);
    return mystrcat(3, pair2 + 1, "-", pair1);
}

tBool is_same_ip_port(tVar ip_header1, tVar ip_header2)
{
    int protocol1 = get_ip_protocol(ip_header1);
    int protocol2 = get_ip_protocol(ip_header2);
    if (protocol1 != protocol2)
        return FALSE;

    size_t addr_len;
    if (is_ip4(protocol1))
    {
        addr_len = sizeof(IP4(ip_header1)->ip_src);
        if (memcmp(&IP4(ip_header1)->ip_src, &IP4(ip_header2)->ip_src, addr_len))
            return FALSE;
        if (memcmp(&IP4(ip_header1)->ip_dst, &IP4(ip_header2)->ip_dst, addr_len))
            return FALSE;
    }
    else
    {
        addr_len = sizeof(IP6(ip_header1)->ip6_src);
        if (memcmp(&IP6(ip_header1)->ip6_src, &IP6(ip_header2)->ip6_src, addr_len))
            return FALSE;
        if (memcmp(&IP6(ip_header1)->ip6_dst, &IP6(ip_header2)->ip6_dst, addr_len))
            return FALSE;
    }

    tByte *upper_layer1 = get_transport_layer_header(ip_header1);
    tByte *upper_layer2 = get_transport_layer_header(ip_header2);

    return (SPORT(upper_layer1) == SPORT(upper_layer2))
        && (DPORT(upper_layer1) == DPORT(upper_layer2));
}

tCString get_ip_pair_from_filename(tCString filename)
{
    tCString ip_port_pair = getbasename(filename);
    tCString suf = strrchr(ip_port_pair, '.');
    if (suf)
        ip_port_pair = strndup(ip_port_pair, suf - ip_port_pair);
    else
        ip_port_pair = strdup(ip_port_pair);

    tString pair2 = strstr(ip_port_pair, "-");
    tString pair1 = strndup(ip_port_pair, pair2 - ip_port_pair);
    pair2 = strdup(pair2 + 1);
    tString dot1 = strrchr(pair1, '.');
    tString dot2 = strrchr(pair2, '.');
    *dot1 = '\0';
    *dot2 = '\0';

    free((tVar)ip_port_pair);
    ip_port_pair = mystrcat(3, pair1, "-", pair2);
    free((tVar)pair1);
    free((tVar)pair2);
    return ip_port_pair;
}

