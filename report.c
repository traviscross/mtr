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
extern char LocalHostname[];
extern char *Hostname;
extern int fstTTL;
extern int maxTTL;
extern int packetsize;
extern int bitpattern;
extern int tos;
extern int MaxPing;


void report_open() {}
void report_close() {
  int i, j, at, max, addr;
  int haddr;
  char name[81];
  char buf[1024];
  char fmt[16];
  int len=0;
  struct hostent *host;

  sprintf(buf, "HOST: %-33s", LocalHostname);
  for( i=0; i<MAXFLD; i++ ) {
    j = fld_index[fld_active[i]];
    if (j < 0) continue;

    sprintf( fmt, "%%%ds", data_fields[j].length );
    sprintf( buf +33+ len, fmt, data_fields[j].title );
    len +=  data_fields[j].length;
  }
  printf("%s\n",buf);

  max = net_max();
  at  = net_min();
  for(; at < max; at++) {
    addr = net_addr(at);
    
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

    len=0;
    sprintf( buf, " %2d. %-33s", at+1, name);
    for( i=0; i<MAXFLD; i++ ) {
      j = fld_index[fld_active [i]];
      if (j < 0) continue;

      /* 1000.0 is a temporay hack for stats usec to ms, impacted net_loss. */
      if( index( data_fields[j].format, 'f' ) ) {
	sprintf( buf +33+ len, data_fields[j].format,
		data_fields[j].net_xxx(at) /1000.0 );
      } else {
	sprintf( buf +33+ len, data_fields[j].format,
		data_fields[j].net_xxx(at) );
      }
      len +=  data_fields[j].length;
    }
    printf("%s\n",buf);
  }
}
void txt_open() {}
void txt_close() { report_close(); }



void xml_open() {}
void xml_close() {
  int i, j, at, max, addr;
  int haddr;
  char name[81];
  struct hostent *host;

  printf("<MTR SRC=%s DST=%s", LocalHostname, Hostname);
  printf(" TOS=0x%X", tos);
  if( packetsize>=0 ){
    printf(" PSIZE=%d", packetsize);
  } else {
    printf(" PSIZE=rand(%d-%d)",MINPACKET, MAXPACKET);
  }
  if( bitpattern>=0 ) {
    printf(" BITPATTERN=0x%02X", (unsigned char)(bitpattern));
  } else {
    printf(" BITPATTERN=rand(0x00-FF)");
  }
  printf(" TESTS=%d>\n", MaxPing);

  max = net_max();
  at  = net_min();
  for(; at < max; at++) {
    addr = net_addr(at);
    
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

    printf("    <HUB COUNT=%d HOST=%s>\n", at+1, name);
    for( i=0; i<MAXFLD; i++ ) {
      j = fld_index[fld_active[i]];
      if (j < 0) continue;

      strcpy(name, "        <%s>");
      strcat(name, data_fields[j].format);
      strcat(name, "</%s>\n");
      /* 1000.0 is a temporay hack for stats usec to ms, impacted net_loss. */
      if( index( data_fields[j].format, 'f' ) ) {
	printf( name,
		data_fields[j].title,
		data_fields[j].net_xxx(at) /1000.0,
		data_fields[j].title );
      } else {
	printf( name,
		data_fields[j].title,
		data_fields[j].net_xxx(at),
		data_fields[j].title );
      }
    }
    printf("    </HUB>\n");
  }
  printf("</MTR>\n");
}

void csv_open() {}
void csv_close() {
  int i, j, at, max, addr;
  int haddr;
  char name[81];
  struct hostent *host;

  /* Caption */
  printf("<SRC=%s DST=%s", LocalHostname, Hostname);
  printf(" TOS=0x%X", tos);
  if( packetsize>=0 ){
    printf(" PSIZE=%d", packetsize);
  } else {
    printf(" PSIZE=rand(%d-%d)",MINPACKET, MAXPACKET);
  }
  if( bitpattern>=0 ) {
    printf(" BITPATTERN=0x%02X", (unsigned char)(bitpattern));
  } else {
    printf(" BITPATTERN=rand(0x00-FF)");
  }
  printf(" TESTS=%d>\n", MaxPing);

  /* Header */
  printf("HUPCOUNT, HOST");
  for( i=0; i<MAXFLD; i++ ) {
      j = fld_index[fld_active[i]];
      if (j < 0) continue; 

      printf( ", %s", data_fields[j].title );
  }
  printf("\n");

  max = net_max();
  at  = net_min();
  for(; at < max; at++) {
    addr = net_addr(at);
    
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

    printf("%d, %s", at+1, name);
    for( i=0; i<MAXFLD; i++ ) {
      j = fld_index[fld_active[j]];
      if (j < 0) continue; 

      /* 1000.0 is a temporay hack for stats usec to ms, impacted net_loss. */
      if( index( data_fields[j].format, 'f' ) ) {
	printf( ", %.2f", data_fields[j].net_xxx(at) / 1000.0);
      } else {
	printf( ", %d",   data_fields[j].net_xxx(at) );
      }
    }
    printf("\n");
  }
}
