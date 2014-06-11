/*
 * Include the appropriate OS header files on Windows and various flavors
 * of UNIX, and also define some additional items and include various
 * non-OS header files on Windows, and; this isolates most of the platform
 * differences to this one file.
 */

#ifndef tcpdump_stdinc_h
#define tcpdump_stdinc_h

#if defined(_WIN32) || defined(WIN32)
# include <stdio.h>
# include <Winsock2.h>
# include <Ws2tcpip.h>
# include <ctype.h>
# include <io.h>
# include <fcntl.h>
# include <sys/types.h>

typedef unsigned char u_char;
typedef unsigned short u_short;
#ifndef HAVE_U_INT8_T
typedef unsigned char u_int8_t;
#endif

#ifndef HAVE_U_INT16_T
typedef unsigned short u_int16_t;
#endif

#ifndef HAVE_U_INT32_T
#if SIZEOF_INT == 4
typedef unsigned int u_int32_t;
#elif SIZEOF_LONG == 4
typedef unsigned long u_int32_t;
#else
#error "there's no appropriate type for u_int32_t"
#endif
#endif /* HAVE_U_INT32_T */

#ifndef HAVE_U_INT64_T
#if SIZEOF_LONG_LONG == 8
typedef unsigned long long u_int64_t;
#elif defined(_MSC_EXTENSIONS)
typedef unsigned _int64 u_int64_t;
#elif SIZEOF_LONG == 8
typedef unsigned long u_int64_t;
#else
#error "there's no appropriate type for u_int64_t"
#endif
#endif /* HAVE_U_INT64_T */

extern const char *inet_ntop (int, const void *, char *, size_t);
extern int inet_pton (int, const char *, void *);
extern int inet_aton (const char *cp, struct in_addr *addr);

#endif /* WIN32 */

#if defined(__GNUC__) && defined(__i386__) && !defined(__ntohl)
  #undef ntohl
  #undef ntohs
  #undef htonl
  #undef htons

  extern __inline__ unsigned long __ntohl (unsigned long x);
  extern __inline__ unsigned short __ntohs (unsigned short x);

  #define ntohl(x)  __ntohl(x)
  #define ntohs(x)  __ntohs(x)
  #define htonl(x)  __ntohl(x)
  #define htons(x)  __ntohs(x)

  extern __inline__ unsigned long __ntohl (unsigned long x)
  {
    __asm__ ("xchgb %b0, %h0\n\t"   /* swap lower bytes  */
             "rorl  $16, %0\n\t"    /* swap words        */
             "xchgb %b0, %h0"       /* swap higher bytes */
            : "=q" (x) : "0" (x));
    return (x);
  }

  extern __inline__ unsigned short __ntohs (unsigned short x)
  {
    __asm__ ("xchgb %b0, %h0"       /* swap bytes */
            : "=q" (x) : "0" (x));
    return (x);
  }
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#define LITTLE_ENDIAN 1234
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#endif /* tcpdump_stdinc_h */
