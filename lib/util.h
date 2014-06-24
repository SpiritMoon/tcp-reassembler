#ifndef MY_UTIL_H
#define MY_UTIL_H

#include <stdio.h>
#include <stdarg.h>
#include "types.h"

#ifdef DEBUG
# define mylogging(...)      myerror(__VA_ARGS__)
#else
# define mylogging(...)      mywarning(__VA_ARGS__)
#endif /* DEBUG */

#define ANSI_RESET          "\x1b[0m"
#define ANSI_BOLD_ON        "\x1b[1m"
#define ANSI_INVERSE_ON     "\x1b[7m"
#define ANSI_BOLD_OFF       "\x1b[22m"
#define ANSI_FG_BLACK       "\x1b[30m"
#define ANSI_FG_RED         "\x1b[31m"
#define ANSI_FG_GREEN       "\x1b[32m"
#define ANSI_FG_YELLOW      "\x1b[33m"
#define ANSI_FG_BLUE        "\x1b[34m"
#define ANSI_FG_MAGENTA     "\x1b[35m"
#define ANSI_FG_CYAN        "\x1b[36m"
#define ANSI_FG_WHITE       "\x1b[37m"
#define ANSI_BG_RED         "\x1b[41m"
#define ANSI_BG_GREEN       "\x1b[42m"
#define ANSI_BG_YELLOW      "\x1b[43m"
#define ANSI_BG_BLUE        "\x1b[44m"
#define ANSI_BG_MAGENTA     "\x1b[45m"
#define ANSI_BG_CYAN        "\x1b[46m"
#define ANSI_BG_WHITE       "\x1b[47m"

#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#define safe_free(x) do {   \
    myfree((tVar)(x));      \
} while(0)


extern void *mymemmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
extern void *mymalloc(size_t size);
extern void *mycalloc(size_t count, size_t size);
extern void myfree(void *x);

extern void lowercase(char *str);
extern char *strnchr(const char *s, char ch, size_t n);
extern void replacechr(char *str, char old, char new);
extern char *mystrdup(const char *s);
extern char *mystrcat(int argc, const char *str1, ...);

extern void myerror(const char *format, ...);
extern void mywarning(const char *format, ...);


#endif /* MY_UTIL_H */
