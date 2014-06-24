#ifndef MY_HTTP_H
#define MY_HTTP_H

#include <stdio.h>
#include "network.h"
#include "http_parser.h"

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
    tByte *data;
    size_t data_len;
} HTTP_STATE;

size_t gzip_fwrite(tByte *data, size_t data_len, FILE *dest);
tCString get_http_filename(tCString url, tCString suffix);
void init_http_settings(http_parser_settings *settings);
void init_http_state();
void reset_http_state();
void update_http_state(tCString dirpath);

#endif /* MY_HTTP_H */
