#ifndef _UTIL_H_INCLUDE_
#define _UTIL_H_INCLUDE_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef _WIN32
# include <Windows.h>
#else
# include <dirent.h>
# include <sys/stat.h>
#endif /* _WIN32 */

#ifndef DEBUG
#define DEBUG
#endif
#ifdef DEBUG
# define mylogging(...)      myerror(__VA_ARGS__)
# define ANSI_RESET          "\x1b[0m"
# define ANSI_BOLD_ON        "\x1b[1m"
# define ANSI_INVERSE_ON     "\x1b[7m"
# define ANSI_BOLD_OFF       "\x1b[22m"
# define ANSI_FG_BLACK       "\x1b[30m"
# define ANSI_FG_RED         "\x1b[31m"
# define ANSI_FG_GREEN       "\x1b[32m"
# define ANSI_FG_YELLOW      "\x1b[33m"
# define ANSI_FG_BLUE        "\x1b[34m"
# define ANSI_FG_MAGENTA     "\x1b[35m"
# define ANSI_FG_CYAN        "\x1b[36m"
# define ANSI_FG_WHITE       "\x1b[37m"
# define ANSI_BG_RED         "\x1b[41m"
# define ANSI_BG_GREEN       "\x1b[42m"
# define ANSI_BG_YELLOW      "\x1b[43m"
# define ANSI_BG_BLUE        "\x1b[44m"
# define ANSI_BG_MAGENTA     "\x1b[45m"
# define ANSI_BG_CYAN        "\x1b[46m"
# define ANSI_BG_WHITE       "\x1b[47m"
#else
# define mylogging(...)      mywarning(__VA_ARGS__)
# define ANSI_RESET          ""
# define ANSI_BOLD_ON        ""
# define ANSI_INVERSE_ON     ""
# define ANSI_BOLD_OFF       ""
# define ANSI_FG_BLACK       ""
# define ANSI_FG_RED         ""
# define ANSI_FG_GREEN       ""
# define ANSI_FG_YELLOW      ""
# define ANSI_FG_BLUE        ""
# define ANSI_FG_MAGENTA     ""
# define ANSI_FG_CYAN        ""
# define ANSI_FG_WHITE       ""
# define ANSI_BG_RED         ""
# define ANSI_BG_GREEN       ""
# define ANSI_BG_YELLOW      ""
# define ANSI_BG_BLUE        ""
# define ANSI_BG_MAGENTA     ""
# define ANSI_BG_CYAN        ""
# define ANSI_BG_WHITE       ""
#endif /* DEBUG */

#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef CHUNK
#undef  CHUNK
#endif
#define CHUNK 16384
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifdef _WIN32
# define PATH_DELIMITER "\\"
#else
# define PATH_DELIMITER "/"
#endif /* __WIN32__ */


typedef int bool;
typedef const unsigned char byte;

bool is_little_endian();

void *mymemmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
void *mymalloc(size_t size);
void *mycalloc(size_t count, size_t size);

void lowercase(char *str);
char *strnchr(const char *s, char ch, size_t n);
void replacechr(char *str, char old, char new);
char *mystrdup(const char *s);
char *mystrcat(int argc, const char *str1, ...);
char *pathcat(const char *dir, const char *filename);
char *url2filename(const char *url);
size_t hexprint(void *ptr, size_t length);
size_t getfilesize(FILE *fp);
int removedir(const char *path);

void myerror(const char *format, ...);
void mywarning(const char *format, ...);


#endif /* _UTIL_H_INCLUDE_ */
