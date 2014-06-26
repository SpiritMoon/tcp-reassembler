/*
 * This is a very troublesome homework...
 *
 * A pcap file structure for tcp transaction is something like this:
 *     [pcap_file_header]
 *     for each packet
 *         [pcap_packet]  this contains packet len info
 *         [ip_header]    usually of size 20 or more
 *         [tcp_header]   usually of size 20 or more
 *         [tcp_data]     len stored in ip header
 */
#include <stdio.h>
#include <string.h>
#include "mydirent.h"
#include "file.h"
#include "util.h"
#include "hash.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "http.h"
#include "main.h"


static inline tByte *get_ip_header_n(HASHNODE *node)
{
    return get_ip_header(((pcap_item *)node->data)->packet);
}

static inline int get_ip_id_n(HASHNODE *node)
{
    return get_ip_id(get_ip_header_n(node));
}

static inline tcp_hdr *get_tcp_header_p(tByte *pcap_packet)
{
    return get_tcp_header(get_ip_header(pcap_packet));
}

static inline tcp_hdr *get_tcp_header_n(HASHNODE *node)
{
    return get_tcp_header_p(((pcap_item *)node->data)->packet);
}
// return beginning memory address of tcp data
static inline tByte *get_tcp_data_n(HASHNODE *node)
{
    return (tByte *)((tString)(get_tcp_header_n(node)) + th_off(get_tcp_header_n(node)) * 4);
}

static inline size_t get_tcp_data_length_p(tByte *pcap_packet)
{
    return get_tcp_data_length(get_ip_header(pcap_packet));
}

static inline size_t get_tcp_data_length_n(HASHNODE *node)
{
    return get_tcp_data_length_p(((pcap_item *)node->data)->packet);
}

static inline tBool is_near_ip_packet_n(HASHNODE *node, HASHNODE *next)
{
    return ((get_ip_id_n(next) - get_ip_id_n(node)) == 1);
}

static inline tBool is_tcp_pdu_n(HASHNODE *node, HASHNODE *next)
{
    tByte *cip_header = get_ip_header_n(node);
    tByte *nip_header = get_ip_header_n(next);
    tcp_hdr *ctcp_pkt = get_tcp_header(cip_header);
    tcp_hdr *ntcp_pkt = get_tcp_header(nip_header);

    return is_same_ip_port(cip_header, nip_header)
        && ctcp_pkt->th_ack == ntcp_pkt->th_ack
        && ntohl(ctcp_pkt->th_seq) < ntohl(ntcp_pkt->th_seq);
}

// hash operation
void free_pcap_item(tVar ptr)
{
    pcap_item *pcap = (pcap_item *)ptr;
    safe_free(pcap->packet);
    safe_free(pcap);
}

/*
 * a pcap item contains a pcap header and a pointer of beignning of packet
 */
pcap_item *create_pcap_item(tByte *pcap_packet, struct pcap_pkthdr *pcap_header)
{
    size_t pcap_len = pcap_header->caplen;
    u_char *tmp_packet = mymalloc(pcap_len);
    memcpy(tmp_packet, pcap_packet, pcap_len);

    pcap_item *pcap = mymalloc(sizeof(pcap_item));
    pcap->header = *pcap_header;
    pcap->packet = tmp_packet;

    return pcap;
}

/*
 * use (source ip:port, destination ip:port) as key, hash pcap_item
 */
tCString hash_pcap_item(tByte *pcap_packet, struct pcap_pkthdr *pcap_header)
{
    tByte *ip_header = get_ip_header(pcap_packet);
    tCString key = get_ip_port_pair(ip_header);
    pcap_item *pcap = create_pcap_item(pcap_packet, pcap_header);

    if ((size_t)(-1) == insert_hash_node(key, (tVar)pcap))
        myerror("insert to hash table failed");
    return key;
}

pcap_t *get_pcap_handle(tCString filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (!(handle = pcap_open_offline(filename, errbuf)))
        myerror("Couldn't open pcap file %s: %s", filename, errbuf);
    return handle;
}


int cmp_pcap_packet(pcap_item *p1, pcap_item *p2)
{
    const u_char *packet1 = p1->packet;
    const u_char *packet2 = p2->packet;
    tcp_hdr *t1 = get_tcp_header_p(packet1);
    tcp_hdr *t2 = get_tcp_header_p(packet2);

    int diff_seq = ntohl(t1->th_seq) - ntohl(t2->th_seq);
    int diff_ack = ntohl(t1->th_ack) - ntohl(t2->th_ack);

    return diff_seq ? diff_seq : diff_ack;
}

/*
 * sort pcap packets storging in hash table
 */
HASHNODE *sort_pcap_packets(HASHNODE *list)
{
    HASHNODE *p, *q, *e, *tail;
    int insize, nmerges, psize, qsize, i;

    if (!list)
        return NULL;

    insize = 1;
    while (1)
    {
        p = list;
        list = NULL;
        tail = NULL;
        /* count number of merges we do in this pass */
        nmerges = 0;

        while (p)
        {
            /* there exists a merge to be done */
            nmerges++;
            /* step `insize' places along from p */
            q = p;
            psize = 0;
            for (i = 0; i < insize; i++)
            {
                psize++;
                if (!(q = q->next))
                    break;
            }

            /* if q hasn't fallen off end, we have two lists to merge */
            qsize = insize;

            /* now we have two lists; merge them */
            while (psize > 0 || (qsize > 0 && q))
            {
                /* decide whether next element of merge comes from p or q */
                if (psize == 0)
                {
                    /* p is empty; e must come from q. */
                    e = q; q = q->next; qsize--;
                }
                else if (qsize == 0 || !q)
                {
                    /* q is empty; e must come from p. */
                    e = p; p = p->next; psize--;
                }
                else if (cmp_pcap_packet((pcap_item *)p->data, (pcap_item *)q->data) <= 0)
                {
                    /* First element of p is lower (or same);
                     * e must come from p. */
                    e = p; p = p->next; psize--;
                }
                else
                {
                    /* First element of q is lower; e must come from q. */
                    e = q; q = q->next; qsize--;
                }

                /* add the next element to the merged list */
                if (tail)
                    tail->next = e;
                else
                    list = e;

                tail = e;
            }

            /* now p has stepped `insize' places along, and q has too */
            p = q;
        }

        tail->next = NULL;

        /* If we have done only one merge, we're finished. */
        if (nmerges <= 1)   /* allow for nmerges==0, the empty list case */
            return list;
        /* Otherwise repeat, merging lists twice the size */
        insize *= 2;
    }
}

void classify_pcap_packets_in_hashtbl()
{
    HASHTBL *hashtbl = get_hash_table();
    HASHITR hashitr = hashtbl_iterator(hashtbl);
    while (hashtbl_next(&hashitr)) {
        size_t i = hashitr.cindex;
        hashtbl->nodes[i] = sort_pcap_packets(hashtbl->nodes[i]);
    }
}

void write_pcap_to_file(pcap_t *handle, HASHNODE *node, tCString dirpath)
{
    tCString filename = pathcat(dirpath, mystrcat(2, node->key, ".pcap"));
    pcap_dumper_t *pd;
    if (!(pd = pcap_dump_open(handle, filename)))
        myerror("create pcap file '%s' failed", filename);

    for (; node; node = node->next)
    {
        pcap_item *pcap = (pcap_item *)node->data;
        pcap_dump((u_char *)pd, &pcap->header, pcap->packet);
    }

    pcap_dump_close(pd);
    safe_free(filename);
}

void write_pcaps_to_files(pcap_t *handle, tCString dirpath)
{
    HASHITR hashitr = hashtbl_iterator(get_hash_table());
    HASHNODE *node;
    while (node = hashtbl_next(&hashitr))
        write_pcap_to_file(handle, node, dirpath);
}


size_t combine_tcp_nodes(tCString key1, tCString key2)
{
    HASHTBL *hashtbl = get_hash_table();
    size_t hash1 = get_hash_index(key1);
    size_t hash2 = get_hash_index(key2);
    HASHNODE *node1;
    HASHNODE *node2;

    // if one nodes is empty, then return another one
    if (hash1 == (size_t)(-1) || !(node1 = hashtbl->nodes[hash1]))
        return hash2;
    if (hash2 == (size_t)(-1) || !(node2 = hashtbl->nodes[hash2]))
        return hash1;

    // make sure of node1 being requester and node2 being responser
    unsigned char flags = get_tcp_header_n(node1)->th_flags;
    if ((flags & TH_SYN) && (flags & TH_ACK))
    {
        size_t tmp = hash1;
        hash1 = hash2;
        hash2 = tmp;
    }

    node2 = hashtbl->nodes[hash2];
    // exchange seq and ack, and append node2 to node1
    while (node2)
    {
        tcp_hdr *tcp_packet2 = get_tcp_header_n(node2);
        tcp_seq seq2 = tcp_packet2->th_seq;
        tcp_seq ack2 = tcp_packet2->th_ack;
        tcp_packet2->th_seq = ack2;
        tcp_packet2->th_ack = seq2;

        HASHNODE *next2 = node2->next;
        node2->next = hashtbl->nodes[hash1];
        hashtbl->nodes[hash1] = node2;
        node2 = next2;
    }

    hashtbl->nodes[hash1] = node1 = sort_pcap_packets(hashtbl->nodes[hash1]);
    // recovery seq and ack in original node2
    while (node1)
    {
        tByte *ip_header2 = get_ip_header_n(node1);
        tCString tmp = get_ip_port_pair(ip_header2);
        if (!strcmp(key2, tmp))
        {
            tcp_hdr *tcp_packet2 = get_tcp_header(ip_header2);
            tcp_seq seq2 = tcp_packet2->th_seq;
            tcp_seq ack2 = tcp_packet2->th_ack;
            tcp_packet2->th_seq = ack2;
            tcp_packet2->th_ack = seq2;
        }
        node1 = node1->next;
        safe_free(tmp);
    }

    node1 = hashtbl->nodes[hash1];
    hashtbl->nodes[hash1] = NULL;
    hashtbl->nodes[hash2] = NULL;
    hash1 = hashtbl->hashfunc(node1->key) % hashtbl->size;
    hashtbl->nodes[hash1] = node1;
    return hash1;
}

// I can find no way to figure it out.
tBool is_same_tcp_node(HASHNODE *node1, HASHNODE *node2)
{
    return FALSE;

    tByte *ip_header1 = get_ip_header_n(node1);
    tByte *ip_header2 = get_ip_header_n(node2);
    tcp_hdr *ctcp_packet = get_tcp_header(ip_header1);
    tcp_hdr *ntcp_packet = get_tcp_header(ip_header2);

    return is_same_ip_port(ip_header1, ip_header2)
        && ctcp_packet->th_seq == ntcp_packet->th_seq
        && ctcp_packet->th_ack == ntcp_packet->th_ack;
}

void filter_tcp_packet(size_t index)
{
    HASHTBL *hashtbl = get_hash_table();
    HASHNODE *node = hashtbl->nodes[index];
    HASHNODE *prev = node;
    HASHNODE *next;

    tBool should_drop;
    while (node)
    {
        next = node->next;
        // if they are duplication packet, then drop it
        should_drop = next ? is_same_tcp_node(node, next) : FALSE;
        // if no data, then skip node
        should_drop |= (0 == get_tcp_data_length_n(node));
        if (should_drop)
        {
            if (hashtbl->nodes[index] == node)
                hashtbl->nodes[index] = next;
            else
                prev->next = next;
            remove_hash_node(node);
        } else {
            prev = node;
        }
        node = next;
    }
}

void tidy_tcp_packet_in_hashtbl()
{
    HASHITR hashitr = hashtbl_iterator(get_hash_table());
    HASHNODE *node;
    while (node = hashtbl_next(&hashitr)) {
        tCString key1 = node->key;
        tCString key2 = reverse_ip_port_pair(key1);
        size_t hash = combine_tcp_nodes(key1, key2);
        filter_tcp_packet(hash);
    }
}

void write_tcp_data_to_file(FILE *fp, HASHNODE *node)
{
    HASHNODE *next = node->next;
    tByte *ip_header = get_ip_header_n(node);
    tcp_hdr *tcp_header = get_tcp_header(ip_header);
    size_t data_len = get_tcp_data_length(ip_header);
    tByte *data_ptr = get_tcp_data(tcp_header);

    if (data_len && data_len != fwrite(data_ptr, 1, data_len, fp))
        mylogging("write wrong size of tcp data to file");

    // if neither nearby packet or PDU, then write a delimiter
    if (next && !(is_near_ip_packet_n(node, next)
               || is_tcp_pdu_n(node, next)))
        fwrite(REQUEST_GAP, 1, REQUEST_GAP_LEN, fp);
}

void write_tcp_data_to_files(tCString dirpath)
{
    HASHITR hashitr = hashtbl_iterator(get_hash_table());
    HASHNODE *node;
    while (node = hashtbl_next(&hashitr)) {
        tCString basename = mystrcat(2, node->key, ".txt");
        tCString filename = pathcat(dirpath, basename);
        FILE *fp = safe_fopen(filename, "w");
        for (; node; node = node->next)
            write_tcp_data_to_file(fp, node);
        fclose(fp);
        safe_free(filename);
        safe_free(basename);
    }
}


void write_http_data_to_dir(tCString filename, tCString dirpath)
{
    DATA_BLOCK datablock = read_file_into_memory(filename);
    tByte *data = datablock.data;
    size_t data_len = datablock.len;
    // if file is empty
    if (0 == data_len)
        return;

    tByte *begin = data;
    tByte *end;
    size_t left_len;
    tByte *token;
    size_t token_len;

    http_parser_settings settings;
    http_parser parser;
    init_http_state();

    do
    {
        // set callback function and execute http parse
        init_http_settings(&settings);
        http_parser_init(&parser, HTTP_BOTH);

        // find the offset of a request or response
        left_len = data + data_len - begin;
        end = (tByte *)mymemmem(begin, left_len, REQUEST_GAP, REQUEST_GAP_LEN);
        token_len = (end == NULL) ? (left_len) : (size_t)(end - begin);
        token = begin;

        size_t nparsed = http_parser_execute(&parser, &settings, (tCString)token, token_len);
        if (nparsed != token_len)
            mywarning("[0x%08X]: %s: %s",
                      (unsigned int)(begin + nparsed - data),
                      filename,
                      http_errno_description(HTTP_PARSER_ERRNO(&parser)));

        // move `begin` cursor to next scan begin
        token += nparsed;
        begin = end + REQUEST_GAP_LEN;
        // skip '\r\n' in http request or response
        while (end && (*begin == '\r' || *begin == '\n'))
            begin++;
        begin = max(begin, token);

        update_http_state(dirpath);
    }
    while (end && left_len > 0);

    reset_http_state();
    safe_free(data);
}

void write_http_data_to_dirs(tCString reqs_dir, tCString dest_dir)
{
    DIR *dir;
    struct dirent *ent;
    if (!(dir = opendir(reqs_dir)))
        myerror("open directory %s failed", reqs_dir);

    for (ent = readdir(dir); ent; ent = readdir(dir))
    {
        tCString filename = ent->d_name;
        if (!match_file_suffix(filename, "txt"))
            continue;
        filename = pathcat(reqs_dir, filename);

        write_http_data_to_dir(filename, dest_dir);

        safe_free(filename);
    }

    closedir(dir);
}


pcap_t *init_environment(int argc, char **argv)
{
    tCString path;
    tCString dir;
#ifdef DEBUG
    path = "test.pcap";
#else
    if (argc < 2)
        myerror("usage: %s [file]", argv[0]);
    path = argv[1];
#endif
    dir = getdirname(path);
    pcap_path = pathcat(dir, PCAP_DIR);
    reqs_path = pathcat(dir, REQS_DIR);
    http_path = pathcat(dir, HTTP_DIR);
    removedir(pcap_path);
    removedir(reqs_path);
    removedir(http_path);
    makedir(pcap_path);
    makedir(reqs_path);
    makedir(http_path);
    set_hash_freefunc(free_pcap_item);
    return get_pcap_handle(path);
}

void reset_environment(pcap_t *handle)
{
    pcap_close(handle);
    safe_free(pcap_path);
    safe_free(reqs_path);
    safe_free(http_path);
}

void hash_all_pcap_item(pcap_t *handle)
{
    struct pcap_pkthdr header;
    tByte *pk;
    for (pk = pcap_next(handle, &header); pk != NULL; pk = pcap_next(handle, &header))
    {
        tByte *ip_header = get_ip_header(pk);
        // skip if neither IPv4 nor IPv6
        if (NULL == ip_header)
            continue;
        if (is_tcp(ip_header))
            hash_pcap_item(pk, &header);
    }
}

int main(int argc, char **argv)
{
    pcap_t *handle = init_environment(argc, argv);
    hash_all_pcap_item(handle);

    classify_pcap_packets_in_hashtbl();
    write_pcaps_to_files(handle, pcap_path);

    tidy_tcp_packet_in_hashtbl();
    write_tcp_data_to_files(reqs_path);
    empty_hash_table();

    write_http_data_to_dirs(reqs_path, http_path);
    // No data to be free
    set_hash_freefunc(NULL);
    destroy_hash_table();

    reset_environment(handle);
    return 0;
}
