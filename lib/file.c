#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "file.h"

size_t hexprint(tByte *byte_ptr, size_t length)
{
    size_t byte_counter = 0;

    while (length--)
    {
        printf("%02X", *byte_ptr);
        byte_ptr++;

        if (++byte_counter)
        {
            if (byte_counter % 16 == 0)
            {
                printf("\n");
            }
            else if (byte_counter % 2 == 0)
            {
                printf(" ");
            }
        }
    }

    printf("\n");
    return byte_counter;
}

tBool match_file_suffix(tCString filename, tCString suffix)
{
    tCString dot = strrchr(filename, '.');
    return dot && !strcmp(dot + 1, suffix);
}

size_t getfilesize(FILE *fp)
{
    fseek(fp, 0, SEEK_END);
    size_t data_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (data_len == (size_t)(-1))
    {
        fclose(fp);
        myerror("call ftell failed\n");
    }
    return data_len;
}

tCString pathcat(tCString dir, tCString filename)
{
    size_t len = strlen(dir);
    char last = *(dir + len - 1);
    if (last == PATH_DELIMITER_C)
        return (tCString)mystrcat(2, dir, filename);
    if (*dir)
        return (tCString)mystrcat(3, dir, PATH_DELIMITER_S, filename);
    else
        return mystrdup(filename);
}

/*
 * get filename from url
 */
tCString url2filename(tCString url)
{
    size_t url_len = strlen(url);
    tCString begin = url;
    tCString end = strchr(url, '?');
    tCString tmp = url;

    // end before first '?'
    end = (end == NULL) ? (url + url_len - 1) : (end - 1);
    // match "/"
    if (begin == end && *begin == '/' && *end == '/')
        return strndup("index", 5);
    // skip all end with '/'
    while (url < end && *end == '/')
        end--;
    // begin after last '/'
    while (tmp < end)
    {
        tmp = strchr(begin, '/');
        if (tmp == NULL || tmp > end)
            break;
        begin = tmp + 1;
    }

    if (begin > end)
        return strndup("unknown", 7);
    return strndup(begin, end - begin + 1);
}

// returns the directory component of a pathname
tCString getdirname(tCString filename)
{
    tCString d = strrchr(filename, PATH_DELIMITER_C);
    if (d)
        return strndup(filename, d - filename);
    return mystrdup("");
}

// returns the final component of a pathname
tCString getbasename(tCString filename)
{
    tCString basename = strrchr(filename, PATH_DELIMITER_C);
    return basename ? mystrdup(basename + 1) : NULL;
}

// WARNING: filename like ".gitignore" will treat all things after "." as a suffix
tCString getfilesuffix(tCString filename)
{
    tCString dot = strrchr(filename, '.');
    return dot ? mystrdup(dot + 1) : NULL;
}

DATA_BLOCK read_file_into_memory(tCString path)
{
    DATA_BLOCK datablock = {
        .data = NULL,
        .len = 0
    };
    FILE *fp = safe_fopen(path, "rb");
    size_t data_len = getfilesize(fp);
    // is a empty file ?
    if (!data_len) {
        fclose(fp);
        return datablock;
    }

    tByte *data = mymalloc(data_len);
    if (fread((tVar)data, 1, data_len, fp) != data_len) {
        fclose(fp);
        mylogging("Couldn't read entire file into memory: %s", path);
        return datablock;
    }

    fclose(fp);
    datablock.data = data;
    datablock.len = data_len;
    return datablock;
}

inline FILE *safe_fopen(const char *path, const char *mode)
{
    FILE *fp = fopen(path, mode);
    if (!fp)
        myerror("Can't open %s for mode '%s'", path, mode);
    return fp;
}
