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
#include <errno.h>
#include <assert.h>
#include <zlib.h>
#include "string.h"
#include "util.h"
#include "hashtbl.h"
#include "http_parser.h"
#include "main.h"
#include "list.h"



// hash operation
/*
 * return a single instance of hash table
 */
static HASHTBL *_g_hashtbl = NULL;
HASHTBL *get_hash_table()
{
    if (_g_hashtbl == NULL)
        _g_hashtbl = hashtbl_create(HASH_SIZE, NULL);
    return _g_hashtbl;
}

/*
 * don't destory hash table until finished all your work!
 */
#define destory_hash_table() do {       \
        hashtbl_destroy(get_hash_table());  \
        _g_hashtbl = NULL;                  \
    } while (0)

void free_hash_node(tVar ptr)
{
    pcap_item *pcap = (pcap_item *)ptr;
    free((tVar)pcap->packet);
    free((tVar)pcap);
}

#define remove_hash_node(node) hashtbl_remove_n(node, 1, free_hash_node)

#define remove_hash_nodes(key) hashtbl_remove(get_hash_table(), key, free_hash_node)

#define get_hash_index(key) hashtbl_index(get_hash_table(), key)

#define get_hash_nodes(key) hashtbl_get(get_hash_table(), key)


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
tCString insert_hash_node(tByte *pcap_packet, struct pcap_pkthdr *pcap_header)
{
    tVar ip_header = get_ip_header(pcap_packet);
    tCString key = get_ip_port_pair(ip_header);
    pcap_item *pcap = create_pcap_item(pcap_packet, pcap_header);

    if ((hash_size)(-1) == hashtbl_insert(get_hash_table(), key, (tVar)pcap))
        myerror("insert to hash table failed");
    return key;
}

pcap_t *get_pcap_handle(tString filename)
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

// file operation

void record_report(tCString filename, tCString format, ...)
{
    tCString filepath = pathcat(REPORT_DIR, filename);
    FILE *fp = fopen(filepath, "a");
    va_list args;
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
    fclose(fp);
    free((tVar)filepath);
}

/*
 * write pcap packet to pcap file
 */
void write_pcap_to_file(pcap_t *handle, HASHNODE *node)
{
    tCString filename = pathcat(PCAP_DIR, mystrcat(2, node->key, ".pcap"));

    pcap_dumper_t *pd;
    if (!(pd = pcap_dump_open(handle, filename)))
        myerror("opening savefile '%s' failed for writing\n", filename);

    while (node)
    {
        pcap_item *pcap = (pcap_item *)node->data;
        struct pcap_pkthdr *pHeader = &pcap->header;
        const u_char *packet = pcap->packet;
        pcap_dump((u_char *)pd, pHeader, packet);
        node = node->next;
    }

    pcap_dump_close(pd);
    free((tVar)filename);
}

void write_pcaps_to_files(pcap_t *handle)
{
    HASHTBL *hashtbl = get_hash_table();

    for (hash_size i = 0; i < hashtbl->size; i++)
    {
        if (!hashtbl->nodes[i])
            continue;
        hashtbl->nodes[i] = sort_pcap_packets(hashtbl->nodes[i]);
        write_pcap_to_file(handle, hashtbl->nodes[i]);
        remove_hash_nodes(hashtbl->nodes[i]->key);
    }
    destory_hash_table();
}


hash_size combine_hash_nodes(tCString key1, tCString key2)
{
    HASHTBL *hashtbl = get_hash_table();
    hash_size hash1 = get_hash_index(key1);
    hash_size hash2 = get_hash_index(key2);
    HASHNODE *node1;
    HASHNODE *node2;

    // if one nodes is empty, then return another one
    if (hash1 == (hash_size)(-1) || !(node1 = hashtbl->nodes[hash1]))
        return hash2;
    if (hash2 == (hash_size)(-1) || !(node2 = hashtbl->nodes[hash2]))
        return hash1;

    // make sure of node1 being requester and node2 being responser
    unsigned char flags = get_tcp_header_n(node1)->th_flags;
    if ((flags & TH_SYN) && (flags & TH_ACK))
    {
        hash_size tmp = hash1;
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
        tVar ip_header2 = get_ip_header_n(node1);
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
        free((tVar)tmp);
    }

    node1 = hashtbl->nodes[hash1];
    hashtbl->nodes[hash1] = NULL;
    hashtbl->nodes[hash2] = NULL;
    assert(node1);
    hash1 = hashtbl->hashfunc(node1->key) % hashtbl->size;
    hashtbl->nodes[hash1] = node1;
    return hash1;
}

tBool is_same_tcp_packet_n(HASHNODE *node1, HASHNODE *node2)
{
    tVar ip_header1 = get_ip_header_n(node1);
    tVar ip_header2 = get_ip_header_n(node2);
    tcp_hdr *ctcp_packet = get_tcp_header(ip_header1);
    tcp_hdr *ntcp_packet = get_tcp_header(ip_header2);

    // TODO: forget this function, I can't find any solution to do this.
    return 0;
    return is_same_ip_port(ip_header1, ip_header2)
           && ctcp_packet->th_seq == ntcp_packet->th_seq
           && ctcp_packet->th_ack == ntcp_packet->th_ack;
}

HASHNODE *combine_tcp_packet(hash_size index)
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
        should_drop = next ? is_same_tcp_packet_n(node, next) : FALSE;
        // if no data, then skip node
        should_drop |= (0 == get_tcp_data_length_n(node));
        if (should_drop)
        {
            if (hashtbl->nodes[index] == node)
                hashtbl->nodes[index] = next;
            else
                prev->next = next;
            free(node->key);
            free_hash_node(node->data);
            free(node);
        }
        else
        {
            prev = node;
        }
        node = next;
    }

    return hashtbl->nodes[index];
}

/*
 * write tcp data (maybe contains HTTP request and response) to txt file
 */
size_t write_tcp_data_to_file(FILE *fp, tByte *data_ptr, size_t data_len)
{
    if (data_len && data_len != fwrite(data_ptr, 1, data_len, fp))
        mylogging("write wrong size of tcp data to file\n");
    return data_len;
}

size_t write_tcp_data_to_file_n(FILE *fp, HASHNODE *node)
{
    tVar ip_header = get_ip_header_n(node);
    tcp_hdr *tcp_header = get_tcp_header(ip_header);
    size_t data_len = get_tcp_data_length(ip_header);
    tByte *data_ptr = get_tcp_data(tcp_header);
    size_t nwrite = write_tcp_data_to_file(fp, data_ptr, data_len);

    HASHNODE *next = node->next;
    // if not nearby packet, then write a delimiter
    if (next && (get_ip_id_n(next) - get_ip_id_n(node) != 1))
        fwrite(REQUEST_GAP, 1, REQUEST_GAP_LEN, fp);
    return nwrite;
}

// read pcap files to memory
#define create_hash_from_directory(dirname) do {                    \
        DIR *dir;                                                       \
        struct dirent *ent;                                             \
        if (!(dir = opendir(dirname)))                                  \
            myerror("open directory '%s' failed\n", dirname);           \
        while ((ent = readdir(dir)) != NULL) {                          \
            tString filename = ent->d_name;                               \
            if (!is_specific_file(filename, "pcap"))                                \
                continue;                                               \
            tString pcap_filename = pathcat(dirname, filename);           \
            \
            const u_char *pcap_packet;                                  \
            struct pcap_pkthdr header;                                  \
            pcap_t *handle = get_pcap_handle(pcap_filename);            \
            while (NULL != (pcap_packet = pcap_next(handle, &header)))  \
                insert_hash_node(pcap_packet, &header);                 \
            \
            pcap_close(handle);                                         \
            free(pcap_filename);                                        \
        }                                                               \
        closedir(dir);                                                  \
    } while (0)

void write_tcp_data_to_files()
{
    create_hash_from_directory(PCAP_DIR);
    // write http requests and responses
    HASHTBL *hashtbl = get_hash_table();
    HASHNODE *node1;
    hash_size hash1;
    tCString key1;
    tCString key2;
    tString filename;

    for (hash_size i = 0; i < hashtbl->size; i++)
    {
        node1 = hashtbl->nodes[i];
        if (!node1)
            continue;

        key1 = node1->key;
        key2 = reverse_ip_port_pair(key1);
        // combin two direction ip:port pair and write to file
        hash1 = combine_hash_nodes(key1, key2);
        // delete all empty nodes (no tcp data)
        node1 = combine_tcp_packet(hash1);
        // skip empty file
        if (!node1)
            continue;
        filename = pathcat(REQS_DIR, mystrcat(2, node1->key, ".txt"));
        FILE *fp = fopen(filename, "wb");
        while (node1)
        {
            write_tcp_data_to_file_n(fp, node1);
            node1 = node1->next;
        }
        fclose(fp);
        free(filename);
        remove_hash_nodes(key1);
        // hashtbl->nodes[hash1] = NULL;
    }
    destory_hash_table();
}

#undef create_hash_from_directory

// HTTP parse
typedef struct
{
    tBool on_continue;
    tBool on_request;
    tBool on_content_type;
    tBool on_content_encoding;
    tBool on_host;
    tBool is_gzip_encoding;
    tString host;
    tString content_type;
    tString url;
    tString data;
    size_t data_len;
} HTTP_info;

static HTTP_info _g_http;

void _init_http_info()
{
    memset(&_g_http, 0, sizeof(_g_http));
    _g_http.on_request = TRUE;
}

void _reset_http_info()
{
    if (_g_http.content_type)
        free(_g_http.content_type);
    if (_g_http.url)
        free(_g_http.url);
    if (_g_http.data)
        free(_g_http.data);
    _g_http.content_type = NULL;
    _g_http.url = NULL;
    _g_http.data = NULL;
    _g_http.on_content_type = FALSE;
    _g_http.on_content_encoding = FALSE;
    _g_http.is_gzip_encoding = FALSE;
    _g_http.on_continue = TRUE;
}

int _on_header_field(http_parser *_, tCString at, size_t length)
{
    // do nothing, just for kill warning
    (void)_;
    _g_http.on_content_type = !strncmp("Content-Type", at, length);
    _g_http.on_content_encoding = !strncmp("Content-Encoding", at, length);
    _g_http.on_host = !strncmp("Host", at, length);
    return 0;
}

int _on_header_value(http_parser *_, tCString at, size_t length)
{
    (void)_;
    if (_g_http.on_content_type)
        _g_http.content_type = strndup(at, length);
    else if (_g_http.on_content_encoding)
        _g_http.is_gzip_encoding = !strncmp(at, "gzip", length);
    else if (_g_http.on_host)
        _g_http.host = strndup(at, length);
    return 0;
}

int _on_headers_complete(http_parser *_)
{
    (void)_;
    _g_http.on_continue = TRUE;
    return 0;
}

int _on_url(http_parser *_, tCString at, size_t length)
{
    (void)_;
    if (_g_http.on_request)
        _g_http.url = strndup(at, length);
    return 0;
}

int _on_body(http_parser *_, tCString at, size_t length)
{
    (void)_;
    if (!_g_http.on_request)
    {
        _g_http.data = mymalloc(length);
        memcpy(_g_http.data, at, length);
        _g_http.data_len = length;
    }
    return 0;
}

size_t gzip_fwrite(tVar data, size_t data_len, FILE *dest)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    if ((ret = inflateInit2(&strm, 15 + 32)) != Z_OK)
        return 0;

    /* decompress until deflate stream ends or end of file */
    size_t done = 0;
    do
    {
        strm.avail_in = MIN(data_len - done, CHUNK);
        strm.next_in = (unsigned char *)data + done;
        done += strm.avail_in;

        /* run inflate() on input until output buffer not full */
        do
        {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            /* state not clobbered */
            switch (ret)
            {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;
            // fall through
            case Z_STREAM_ERROR:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                goto END;
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest))
                goto END;
        }
        while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    }
    while (done < data_len && ret != Z_STREAM_END);

END:
    /* clean up and return */
    (void)inflateEnd(&strm);
    tCString prefix = ANSI_FG_CYAN "gzip_fwrite" ANSI_RESET;
    switch (ret)
    {
    case Z_ERRNO:
        if (ferror(dest))
            mywarning("%s: writing stdout\n", prefix);
        break;
    case Z_STREAM_ERROR:
        mywarning("%s: invalid compression level\n", prefix);
        break;
    case Z_DATA_ERROR:
        mywarning("%s: invalid or incomplete deflate data\n", prefix);
        break;
    case Z_MEM_ERROR:
        mywarning("%s: out of memory\n", prefix);
        break;
    case Z_VERSION_ERROR:
        mywarning("%s: zlib version mismatch!\n", prefix);
        break;
    case Z_STREAM_END:
    // fall through
    default:
        break;
    }
    return MIN(done, data_len);
}

tString get_http_filename(tCString url, tCString suf)
{
    tString basename = url2filename(url);
    if (!strrchr(basename, '.'))
    {
        tString tmp = basename;
        basename = mystrcat(3, basename, ".", suf);
        free(tmp);
    }
    return basename;
}

tCString create_http_dirs(tCString rootdir)
{
    tCString dirpath = pathcat(HTTP_DIR, rootdir);
    if (0 != makedir(dirpath))
    {
        if (errno == EEXIST)
            return dirpath;
        myerror("create directory %s failed", dirpath);
    }
    tCString image_dir = pathcat(dirpath, "images");
    tCString js_dir = pathcat(dirpath, "js");
    tCString css_dir = pathcat(dirpath, "css");
    makedir(image_dir);
    makedir(js_dir);
    makedir(css_dir);
    free((tVar)image_dir);
    free((tVar)js_dir);
    free((tVar)css_dir);
    return dirpath;
}

tCString write_http_block_to_dir(tCString dirpath)
{
    if (!_g_http.url || !_g_http.data || !_g_http.content_type)
        return NULL;
    tString suffix = get_http_file_suffix(_g_http.content_type);
    if (!strcmp(suffix, "js"))
        dirpath = pathcat(dirpath, "js");
    else if (!strcmp(suffix, "css"))
        dirpath = pathcat(dirpath, "css");
    else if (!strcmp(suffix, "jpg")
             || !strcmp(suffix, "jpeg")
             || !strcmp(suffix, "png")
             || !strcmp(suffix, "gif"))
        dirpath = pathcat(dirpath, "images");
    else
        dirpath = strdup(dirpath);
    tString basename = get_http_filename(_g_http.url, suffix);
    tString filename = pathcat(dirpath, basename);

    FILE *fp = fopen(filename, "ab");
    if (!fp)
        mylogging("can't open %s for write\n", filename);

    size_t wlen;
    if (_g_http.is_gzip_encoding)
        wlen = gzip_fwrite(_g_http.data, _g_http.data_len, fp);
    else
        wlen = fwrite(_g_http.data, 1, _g_http.data_len, fp);
    if (wlen != _g_http.data_len)
        mywarning("should write %u bytes to %s, but %u done\n", _g_http.data_len, filename, wlen);
    free((tVar)dirpath);
    free(filename);
    free(suffix);
    fclose(fp);
    return basename;
}

void write_http_data_to_dir(tCString data, size_t data_len, tCString filename)
{
    // init http parser
    http_parser_settings settings;
    http_parser parser;
    _init_http_info();

    tCString srcname = getbasename(filename);
    tCString begin = data;
    tCString end;
    tCString ptr;
    tVar token;
    size_t left_len;
    size_t token_len;

    do
    {
        if (!data_len)
            break;
        // get a request or response string
        left_len = data + data_len - begin;
        end = (tCString)mymemmem(begin, left_len, REQUEST_GAP, REQUEST_GAP_LEN);
        token_len = (end == NULL) ? (left_len) : (size_t)(end - begin);
        token = mymalloc(token_len);
        memcpy(token, begin, token_len);
        ptr = begin;

        // set callback function and execute http parse
        memset(&settings, 0, sizeof(settings));
        settings.on_url = _on_url;
        settings.on_body = _on_body;
        settings.on_header_field = _on_header_field;
        settings.on_header_value = _on_header_value;
        settings.on_headers_complete = _on_headers_complete;
        http_parser_init(&parser, HTTP_BOTH);
        size_t nparsed = http_parser_execute(&parser, &settings, token, token_len);
        free(token);

        if (nparsed != token_len)
        {
#ifndef DEBUG
            // #ifdef DEBUG
            // pretty debug mylogging
            mywarning(ANSI_FG_GREEN "[0x%08X]:" ANSI_RESET
                      ANSI_FG_CYAN " %s" ANSI_RESET ": "
                      ANSI_FG_RED "%s" ANSI_RESET,
                      (unsigned int)(begin + nparsed - data),
                      srcname,
                      http_errno_description(HTTP_PARSER_ERRNO(&parser)));
#endif /* DEBUG */
        }
        // move begin cursor to next scan
        ptr += nparsed;
        begin = end + REQUEST_GAP_LEN;
        // skip '\r\n' in http request or response
        while (end && (*begin == '\r' || *begin == '\n'))
            begin++;
        begin = MAX(begin, ptr);

        // update _g_http state
        if (!_g_http.on_request)
        {
            tCString host = _g_http.host;
            if (host)
            {
                tCString dirpath = create_http_dirs(host);
                tCString http_filename = write_http_block_to_dir(dirpath);
                if (http_filename)
                {
                    record_report("GET_to.txt", "%s->%s\n", srcname, http_filename);
                }
                free((tVar)dirpath);
                free((tVar)http_filename);
            }
            _reset_http_info();
        }
        _g_http.on_request = !_g_http.on_request;
    }
    while (end && left_len > 0);

    _reset_http_info();
}

void write_http_data_to_dirs()
{
    DIR *dir;
    struct dirent *ent;
    if (!(dir = opendir(REQS_DIR)))
        myerror("open directory '" REQS_DIR "' failed");

    while ((ent = readdir(dir)) != NULL)
    {
        // deal with filename
        tCString filename = ent->d_name;
        if (!is_specific_file(filename, "txt"))
            continue;
        // a directory stores a website's HTTP files
        filename = pathcat(REQS_DIR, filename);
        FILE *fp = fopen(filename, "rb");
        if (!fp)
            mylogging("can't open %s for http parse", filename);
        size_t data_len = getfilesize(fp);
        tVar data = mymalloc(data_len);
        if (fread(data, 1, data_len, fp) != data_len)
        {
            free(data);
            mylogging("couldn't read entire file\n");
        }
        else
        {
            write_http_data_to_dir(data, data_len, filename);
            free(data);
        }

        fclose(fp);
    }
    closedir(dir);
}


static list_t *_file_list = NULL;
list_t *get_file_list()
{
    if (!_file_list)
        _file_list = list_new();
    return _file_list;
}

void list_insert_head(tCString filename)
{
    tCString buf = strdup(filename);
    list_node_t *node = list_node_new((tVar)buf);
    list_lpush(get_file_list(), node);
}

void list_insert_tail(tCString filename)
{
    tCString buf = strdup(filename);
    list_node_t *node = list_node_new((tVar)buf);
    list_rpush(get_file_list(), node);
}

void traverse_http_diretory(tCString path)
{
    DIR *d = opendir(path);

    if (d)
    {
        struct dirent *p;
        while (NULL != (p = readdir(d)))
        {
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
                continue;

            tString buf = pathcat(path, p->d_name);
            struct stat statbuf;
            if (!stat(buf, &statbuf))
            {
                if (S_ISDIR(statbuf.st_mode))
                {
                    traverse_http_diretory(buf);
                }
                else
                {
                    tCString suffix = getfilesuffix(buf);
                    if (!strcmp(suffix, "htm") || !strcmp(suffix, "html"))
                        list_insert_head(buf);
                    else
                        list_insert_tail(buf);
                }
            }
            free(buf);
        }
        closedir(d);
    }
}


void init_environment(int argc, char **argv)
{
    if (argc < 2)
        myerror("usage: %s [file]", argv[0]);
    removedir(REPORT_DIR);
    removedir(PCAP_DIR);
    removedir(REQS_DIR);
    removedir(HTTP_DIR);
    makedir(REPORT_DIR);
    makedir(PCAP_DIR);
    makedir(REQS_DIR);
    makedir(HTTP_DIR);
}

int main(int argc, char **argv)
{
    const u_char *pcap_packet;
    struct pcap_pkthdr header;
    pcap_t *handle;

    init_environment(argc, argv);
    handle = get_pcap_handle(argv[1]);
    while (NULL != (pcap_packet = pcap_next(handle, &header)))
    {
        tVar ip_header = get_ip_header(pcap_packet);
        // skip if neither IPv4 nor IPv6
        if (NULL == ip_header)
            continue;
        // TODO: skip IPv6 because I can't hold it ╮(╯_╰)╭
        if (is_ip6(get_ip_protocol(ip_header)))
            continue;
        if (is_tcp(ip_header))
        {
            insert_hash_node(pcap_packet, &header);
        }
        else if (is_udp(ip_header))
        {
            // TODO: deal with UDP
        }
    }

    write_pcaps_to_files(handle);
    write_tcp_data_to_files();
    write_http_data_to_dirs();
    DIR *dir;
    struct dirent *ent;
    if (!(dir = opendir(HTTP_DIR)))
        myerror("open directory '%s' failedn", HTTP_DIR);
    while ((ent = readdir(dir)) != NULL)
    {
        tString filename = ent->d_name;
        if (!strcmp(filename, ".") || !strcmp(filename, ".."))
            continue;
        tCString basename;
        tCString dirname;
        filename = pathcat(HTTP_DIR, filename);
        traverse_http_diretory(filename);

        list_node_t *node = get_file_list()->head;
        if (node)
        {
            dirname = getdirname(node->val);
            record_report("files.txt", "%s: ", dirname);
            free((tVar)dirname);

            basename = getbasename(node->val);
            tCString suffix = getfilesuffix(basename);
            if (!strcmp(suffix, "htm") || !strcmp(suffix, "html"))
                record_report("refer.txt", "%s: ", basename);
            else
            {
                if (get_file_list()->len == 1)
                    record_report("refer.txt", "%s", basename);
                else
                    record_report("refer.txt", "%s + ", basename);
            }
            node = node->next;
            if (node)
                record_report("files.txt", "%s + ", basename);
            else
                record_report("files.txt", "%s", basename);
        }
        while (node)
        {
            basename = getbasename(node->val);
            if (node->next)
            {
                record_report("refer.txt", "%s + ", basename);
                record_report("files.txt", "%s + ", basename);
            }
            else
            {
                record_report("refer.txt", "%s", basename);
                record_report("files.txt", "%s", basename);
            }
            node = node->next;
        }
        record_report("refer.txt", "\n\n");
        record_report("files.txt", "\n\n");
        free((tVar)filename);
        list_destroy(get_file_list());
        _file_list = NULL;
    }
    closedir(dir);
    pcap_close(handle);
    return 0;
}
