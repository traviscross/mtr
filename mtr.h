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

#ifndef MTR_MTR_H
#define MTR_MTR_H

#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

#ifdef __GNUC__
#define UNUSED __attribute__((__unused__))
#else
#define UNUSED
#endif

/* stuff used by display such as report, curses... */
#define MAXFLD 20		/* max stats fields to display */

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

extern char *
trim(char * s);

struct mtr_ctl {
  int MaxPing;
  float WaitTime;
  float GraceTime;
  char *Hostname;
  char *InterfaceAddress;
  char LocalHostname[128];
  int ipinfo_no;
  int ipinfo_max;
  int iiwidth_len;
  int cpacketsize;		/* packet size used by ping */
  int bitpattern;		/* packet bit pattern used by ping */
  int tos;			/* type of service set in ping packet*/
#ifdef SO_MARK
  uint32_t mark;
#endif
  ip_t unspec_addr;
  int af;			/* address family of remote target */
  int mtrtype;			/* type of query packet used */
  int fstTTL;			/* initial hub(ttl) to ping byMin */
  int maxTTL;			/* last hub to ping byMin*/
  int maxUnknown;		/* stop ping threshold */
  int remoteport;		/* target port for TCP tracing */
  int localport;		/* source port for UDP tracing */
  int tcp_timeout;		/* timeout for TCP connections */
  unsigned char fld_active[2 * MAXFLD];	/* SO_MARK to set for ping packet*/
  int fld_index[256];		/* default display field (defined by key in net.h) and order */
  char available_options[MAXFLD];
  int display_offset;		/* only used in text mode */
  void *gtk_data;		/* pointer to hold arbitrary gtk data */
  unsigned int			/* bit field to hold named booleans */
    ForceMaxPing:1,
    use_dns:1,
    show_ips:1,
    enablempls:1,
    dns:1,
    reportwide:1,
    Interactive:1,
    display_mode:2,
    DisplayMode:5;
};

#endif /* MTR_MTR_H */
