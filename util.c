#include "util.h"

bool is_little_endian()
{
    unsigned int i = 1;
    return *(char *)&i;
}

void *mymemmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    const char *ptr = (const char *)haystack;
    const char *end = (const char *)haystack + haystacklen - needlelen + 1;
    const char firstch = *(const char *)needle;
    size_t count;

    while (ptr < end) {
        ptr = memchr(ptr, firstch, end - ptr);
        if (!ptr)
            return NULL;
        count = 0;
        while (count != needlelen && *(ptr + count) == *((const char *)needle + count))
            count++;
        if (count == needlelen)
            return (void *)ptr;
        ptr += count;
    }

    return NULL;
}

void *mymalloc(size_t size)
{
    void *ptr = malloc(size);
    if (!ptr)
        myerror("alloc memory failed\n");
    return ptr;
}

void *mycalloc(size_t count, size_t size)
{
    void *ptr = calloc(count, size);
    if (!ptr)
        myerror("alloc memory failed\n");
    return ptr;
}

char *strnchr(const char *s, char ch, size_t n) {
    while (n--) {
        if (*s == ch)
            break;
        s++;
    }
    if (n == 0 && *s != ch)
        return NULL;
    return (char *)s;
}

void replacechr(char *str, char old, char new) {
    char *ptr;
    while (1) {
        ptr = strchr(str, old);
        if(ptr == NULL)
            break;
        str[(int)(ptr - str)]=new;
    }
}

void lowercase(char *str) {
    while (*str){
        if ('Z' >= *str && *str >= 'A')
            *str = *str - 'A' + 'a';
        str++;
    }
}

char *mystrdup(const char *s)
{
    char *b;
    if (!(b = mymalloc(strlen(s) + 1))) return NULL;
    strcpy(b, s);
    return b;
}

void myerror(const char *format, ...)
{
    fprintf(stderr, ANSI_FG_RED);
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, ANSI_RESET "\n");
    exit(EXIT_FAILURE);
}

void mywarning(const char *format, ...)
{
    fprintf(stderr, ANSI_FG_YELLOW);
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, ANSI_RESET "\n");
}

char *mystrcat(int argc, const char *str1, ...)
{
    va_list strs;
    va_start(strs, str1);
    char *ss = strdup(str1);
    unsigned long len = strlen(ss);

    for (int i = 0; i < argc - 1; i++)
    {
        const char *s = va_arg(strs, const char *);
        len += strlen(s);
        // 1 for '\0'
        if (!(ss = realloc(ss, len + 1)))
            myerror("alloc memory for `mystrcat` function failed");
        ss[len] = '\0';
        strcat(ss, s);
    }

    va_end(strs);
    return ss;
}

char *pathcat(const char *dir, const char *filename)
{
    return mystrcat(3, dir, PATH_DELIMITER, filename);
}

char *url2filename(const char *url) {
    size_t url_len = strlen(url);
    const char *begin = url;
    const char *end = strchr(url, '?');
    const char *tmp = url;

    // end before first '?'
    end = (end == NULL) ? (url + url_len - 1) : (end - 1);
    // match "/"
    if (begin == end && *begin == '/' && *end == '/')
        return strndup("index", 5);
    // skip all end with '/'
    while (url < end && *end == '/')
        end--;
    // begin after last '/'
    while (tmp < end) {
        tmp = strchr(begin, '/');
        if (tmp == NULL || tmp > end)
            break;
        begin = tmp + 1;
    }

    if (begin > end)
        return strndup("unknown", 7);
    else
        return strndup(begin, end - begin + 1);
}

size_t hexprint(void *ptr, size_t length)
{
    size_t byte_counter = 0;
    char *byte_ptr = (char *)ptr;

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

size_t getfilesize(FILE *fp) {
    fseek(fp, 0, SEEK_END);
    size_t data_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (data_len == -1) {
        fclose(fp);
        myerror("call ftell failed\n");
    }
    return data_len;
}
