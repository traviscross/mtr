/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball
    Copyright (C) 2005 R.E.Wolff@BitWizard.nl

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* Typedefs */

/*  Find the proper type for 8 bits  */
#if SIZEOF_UNSIGNED_CHAR == 1
typedef unsigned char uint8;
#else
#error No 8 bit type
#endif

/*  Find the proper type for 16 bits  */
#if SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short uint16;
#elif SIZEOF_UNSIGNED_INT == 2
typedef unsigned int uint16;
#elif SIZEOF_UNSIGNED_LONG == 2
typedef unsigned long uint16;
#else
#error No 16 bit type
#endif

/*  Find the proper type for 32 bits  */
#if SIZEOF_UNSIGNED_SHORT == 4
typedef unsigned short uint32;
#elif SIZEOF_UNSIGNED_INT == 4
typedef unsigned int uint32;
#elif SIZEOF_UNSIGNED_LONG == 4
typedef unsigned long uint32;
#else
#error No 32 bit type
#endif

typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned long dword;

#ifdef ENABLE_IPV6
typedef struct in6_addr ip_t;
#else
typedef struct in_addr ip_t;
#endif

extern int enablempls;
extern int dns;
extern int show_ips;
extern int use_dns;

#ifdef __GNUC__
#define UNUSED __attribute__((__unused__))
#else
#define UNUSED
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t; 
#endif

extern char *
trim(char * s);
