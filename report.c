/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

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

#include <config.h>
#include <sys/types.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>

#include "report.h"
#include "net.h"

extern int dns;

void report_open() {
  printf("%-40s LOSS  RCVD  SENT BEST   AVG  WORST\n", "HOST");
  fflush(stdout);
}

void report_close() {
  int at, max, addr;
  int haddr;
  char name[81];
  struct hostent *host;

  max = net_max();

  for(at = 0; at < max; at++) {
    addr = net_addr(at);
    
    strcpy(name, "");
    if(addr == 0) {
      sprintf(name, "???");
    } else {
      haddr = htonl(addr);
      host = dns?gethostbyaddr((char *)&haddr, sizeof(int), AF_INET):NULL;

      if (host != NULL) {
	 strncpy(name, host->h_name, 80);
	 name[80] = 0;
      } else {
	sprintf(name, "%d.%d.%d.%d", (addr >> 24) & 0xff, (addr >> 16) & 0xff, 
		(addr >> 8) & 0xff, addr & 0xff);
      }
    }

    printf("%-40s%5d%%%6d%5d%6d%6d%6d\n", name,     
	     net_percent(at),
             net_returned(at), net_xmit(at),
             net_best(at)/1000, net_avg(at)/1000, net_worst(at)/1000);
  }
}



