#ifndef _UTILS_H
#define _UTILS_H

// Fend off -Wunused-parameter
#if defined(__GNUC__)
# define UNUSED __attribute__((__unused__))
#else
# define UNUSED
#endif

// Number of entries in a fixed-length array
#define N_ENTRIES(x) (sizeof(x) / sizeof(*x))

#endif
