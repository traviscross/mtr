/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1998  R.E.Wolff@BitWizard.nl

    raw.c -- raw output (for logging for later analysis)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "raw.h"
#include "net.h"
#include "dns.h"

static int havename[MaxHost];

#if 0
static char *addr_to_str(int addr)
{
  static char buf[20];

  sprintf (buf, "%d.%d.%d.%d", 
	   (addr >> 0)  & 0xff, 
	   (addr >> 8)  & 0xff, 
	   (addr >> 16) & 0xff, 
	   (addr >> 24) & 0xff);
  return buf;
}
#endif

void raw_rawping (int host, int msec)
{
  char *name;

  if (!havename[host]) {
    name = dns_lookup2(net_addr(host));
    if (name) {
      havename[host]++;
      printf ("d %d %s\n", host, name);
    }
  }
  printf ("p %d %d\n", host, msec);
  fflush (stdout); 
}


void raw_rawhost (int host, int ip_addr)
{
  struct in_addr in;

  in.s_addr = ip_addr;

  printf ("h %d %s\n", 
	  host, inet_ntoa(in));
  fflush (stdout); 
}




