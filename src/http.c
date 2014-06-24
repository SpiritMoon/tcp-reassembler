#include <zlib.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"
#include "file.h"
#include "hash.h"
#include "http.h"

static HTTP_STATE _http_state;

static int on_header_field(http_parser *_, tCString at, size_t length)
{
    _http_state.on_content_type = !strncmp("Content-Type", at, length);
    _http_state.on_content_encoding = !strncmp("Content-Encoding", at, length);
    _http_state.on_host = !strncmp("Host", at, length);
    return 0;
}

static int on_header_value(http_parser *_, tCString at, size_t length)
{
    if (_http_state.on_content_type)
        _http_state.content_type = strndup(at, length);
    else if (_http_state.on_content_encoding)
        _http_state.is_gzip_encoding = !strncmp(at, "gzip", length);
    else if (_http_state.on_host)
        _http_state.host = strndup(at, length);
    return 0;
}

static int on_headers_complete(http_parser *_)
{
    _http_state.on_continue = TRUE;
    return 0;
}

static int on_url(http_parser *_, tCString at, size_t length)
{
    if (_http_state.on_request)
        _http_state.url = strndup(at, length);
    return 0;
}

static int on_body(http_parser *_, tCString at, size_t length)
{
    if (_http_state.on_request)
        return 0;
    _http_state.data = mymalloc(length);
    memcpy((tVar)_http_state.data, at, length);
    _http_state.data_len = length;
    return 0;
}

size_t gzip_fwrite(tByte *data, size_t data_len, FILE *dest)
{
    unsigned char out[CHUNK];
    z_stream strm;
    int ret;

    memset(&strm, 0, sizeof(z_stream));
    if ((ret = inflateInit2(&strm, 15 + 32)) != Z_OK)
        return 0;

    /* decompress until deflate stream ends or end of file */
    size_t done = 0;
    unsigned have;
    do
    {
        strm.avail_in = min(data_len - done, CHUNK);
        strm.next_in = (Bytef *)(data + done);
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

    }
    /* done when inflate() says it's done */
    while (done < data_len && ret != Z_STREAM_END);

    /* clean up and return */
END:
    inflateEnd(&strm);
    tCString prefix = "gzip_fwrite";
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
    return min(done, data_len);
}

tCString get_http_filename(tCString url, tCString suffix)
{
    tCString basename = url2filename(url);
    if (!strrchr(basename, '.'))
    {
        tCString tmp = basename;
        basename = mystrcat(3, basename, ".", suffix);
        safe_free(tmp);
    }
    return basename;
}

void init_http_settings(http_parser_settings *settings)
{
    memset(settings, 0, sizeof(http_parser_settings));
    settings->on_url = on_url;
    settings->on_body = on_body;
    settings->on_header_field = on_header_field;
    settings->on_header_value = on_header_value;
    settings->on_headers_complete = on_headers_complete;
}

void init_http_state()
{
    memset(&_http_state, 0, sizeof(_http_state));
    _http_state.on_request = TRUE;
}

void reset_http_state()
{
    safe_free(_http_state.content_type);
    safe_free(_http_state.url);
    safe_free(_http_state.data);
    _http_state.content_type = NULL;
    _http_state.url = NULL;
    _http_state.data = NULL;
    _http_state.on_content_type = FALSE;
    _http_state.on_content_encoding = FALSE;
    _http_state.is_gzip_encoding = FALSE;
    _http_state.on_continue = TRUE;
}

static void write_http_block_to_dir(tCString dirpath)
{
    tCString suffix = get_http_file_suffix(_http_state.content_type);
    tCString basename = get_http_filename(_http_state.url, suffix);
    tCString filename = pathcat(dirpath, basename);

    FILE *fp = safe_fopen(filename, "ab");

    size_t nwrited;
    if (_http_state.is_gzip_encoding)
        nwrited = gzip_fwrite(_http_state.data, _http_state.data_len, fp);
    else
        nwrited = fwrite(_http_state.data, 1, _http_state.data_len, fp);
    if (nwrited != _http_state.data_len)
        mywarning("write_http_block_to_dir: writed %u/%u (bytes) to %s",
                  _http_state.data_len,
                  nwrited,
                  filename);

    fclose(fp);
    safe_free(filename);
    safe_free(basename);
    safe_free(suffix);
}

void update_http_state(tCString dirpath)
{
    if (!_http_state.on_request)
    {
        tCString host = _http_state.host;
        if (host)
        {
            dirpath = pathcat(dirpath, host);
            if (-1 == get_hash_index(dirpath)) {
            // if (!is_hash_key_exist(dirpath)) {
                insert_hash_node(dirpath, NULL);
                makedir(dirpath);
            }
            if (_http_state.url && _http_state.data && _http_state.content_type)
                write_http_block_to_dir(dirpath);
            safe_free(dirpath);
        }
        reset_http_state();
    }
    _http_state.on_request = !_http_state.on_request;
}
