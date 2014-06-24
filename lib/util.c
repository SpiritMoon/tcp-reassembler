#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "util.h"

inline void myfree(void *x)
{
    if (x)
        free(x);
}

void *mymemmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
    const char *ptr = (const char *)haystack;
    const char *end = (const char *)haystack + haystacklen - needlelen + 1;
    const char firstch = *(const char *)needle;
    size_t count;

    while (ptr < end)
    {
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
    assert(ptr);
    return ptr;
}

void *mycalloc(size_t count, size_t size)
{
    void *ptr = calloc(count, size);
    assert(ptr);
    return ptr;
}

char *strnchr(const char *s, char ch, size_t n)
{
    while (n--)
    {
        if (*s == ch)
            break;
        s++;
    }
    if (n == 0 && *s != ch)
        return NULL;
    return (char *)s;
}

void replacechr(char *str, char old, char new)
{
    char *ptr;
    while (1)
    {
        ptr = strchr(str, old);
        if (ptr == NULL)
            break;
        str[(int)(ptr - str)] = new;
    }
}

void lowercase(char *str)
{
    while (*str)
    {
        if ('Z' >= *str && *str >= 'A')
            *str = *str - 'A' + 'a';
        str++;
    }
}

char *mystrdup(const char *s)
{
    char *b = mymalloc(strlen(s) + 1);
    assert(b);
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
#ifdef DEBUG
    FILE *fp = stderr;
#else
    FILE *fp = safe_fopen("warning.log", "a");
#endif /* DEBUG */
    fprintf(fp, ANSI_FG_YELLOW);
    va_list args;
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
    fprintf(fp, ANSI_RESET "\n");
#ifndef DEBUG
    fclose(fp);
#endif /* DEBUG */
}

char *mystrcat(int argc, const char *str1, ...)
{
    va_list strs;
    va_start(strs, str1);
    char *ss = mystrdup(str1);
    unsigned long len = strlen(ss);

    for (int i = 0; i < argc - 1; i++)
    {
        const char *s = va_arg(strs, const char *);
        len += strlen(s);
        // 1 for '\0'
        if (!(ss = realloc(ss, len + 1)))
            myerror("alloc memory for `mystrcat` function failed");
        assert(ss);
        ss[len] = '\0';
        strcat(ss, s);
    }

    va_end(strs);
    return ss;
}
