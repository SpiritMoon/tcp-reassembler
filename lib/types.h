#ifndef MY_TYPES_H
#define MY_TYPES_H


#include <stddef.h>
#include <stdint.h>

#ifndef _U_INT
#define _U_INT
typedef unsigned int            u_int;
#endif /* _U_INT */
#ifndef _U_SHORT
#define _U_SHORT
typedef unsigned short          u_short;
#endif /* _U_SHORT */
#ifndef _U_CHAR
#define _U_CHAR
typedef unsigned char           u_char;
#endif /* _U_CHAR */
#ifndef _U_LONG
#define _U_LONG
typedef unsigned long           u_long;
#endif /* _U_LONG */

#ifndef _INT8_T
#define _INT8_T
typedef signed char             int8_t;
#endif /* _INT8_T */
#ifndef _INT16_T
#define _INT16_T
typedef signed short            int16_t;
#endif /* _INT16_T */
#ifndef _INT32_T
#define _INT32_T
typedef signed int              int32_t;
#endif /* _INT32_T */
#ifndef _INT64_T
#define _INT64_T
typedef signed long long        int64_t;
#endif /* _INT64_T */
#ifndef _UINT8_T
#define _UINT8_T
typedef unsigned char           uint8_t;
#endif /* _UINT8_T */
#ifndef _UINT16_T
#define _UINT16_T
typedef unsigned short          uint16_t;
#endif /* _UINT16_T */
#ifndef _UINT32_T
#define _UINT32_T
typedef unsigned int            uint32_t;
#endif /* _UINT32_T */
#ifndef _UINT64_T
#define _UINT64_T
typedef unsigned long long      uint64_t;
#endif /* _UINT64_T */
#ifndef _U_INT8_T
#define _U_INT8_T
typedef unsigned char           u_int8_t;
#endif /* _U_INT8_T */
#ifndef _U_INT16_T
#define _U_INT16_T
typedef unsigned short          u_int16_t;
#endif /* _U_INT16_T */
#ifndef _U_INT32_T
#define _U_INT32_T
typedef unsigned int            u_int32_t;
#endif /* _U_INT32_T */
#ifndef _U_INT64_T
#define _U_INT64_T
typedef unsigned long long      u_int64_t;
#endif /* _U_INT64_T */

typedef void *                  tVar;
typedef char *                  tString;
typedef const char *            tCString;
typedef int                     tBool;
typedef const unsigned char     tByte;

#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif


#endif /* MY_TYPES_H */
