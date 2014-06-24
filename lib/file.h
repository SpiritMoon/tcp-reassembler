#ifndef MY_FILE_H
#define MY_FILE_H

#ifdef _WIN32
# include <Windows.h>
# define PATH_DELIMITER_S "\\"
#else
# include <sys/stat.h>
# define PATH_DELIMITER_S "/"
#endif /* __WIN32__ */
# define PATH_DELIMITER_C (*PATH_DELIMITER_S)

#include <stdio.h>
#include "types.h"

typedef struct
{
    tByte *data;
    size_t len;
} DATA_BLOCK;

extern FILE *safe_fopen(const char *path, const char *mode);
extern int makedir(tCString path);
extern int removedir(tCString path);
extern size_t hexprint(tByte *byte_ptr, size_t length);
extern tBool match_file_suffix(tCString filename, tCString suffix);
extern size_t getfilesize(FILE *fp);
// blow functions will allocate memory for return value
extern tCString pathcat(tCString dir, tCString filename);
extern tCString url2filename(tCString url);
extern tCString getdirname(tCString filename);
extern tCString getbasename(tCString filename);
extern tCString getfilesuffix(tCString filename);
extern DATA_BLOCK read_file_into_memory(tCString path);

#endif /* MY_FILE_H */
