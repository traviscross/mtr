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
#include <strings.h>

#include "mtr.h"
#include "report.h"
#include "net.h"
#include "dns.h"

extern int dns;
extern char LocalHostname[];
extern char *Hostname;
extern int fstTTL;
extern int maxTTL;
extern int cpacketsize;
extern int bitpattern;
extern int tos;
extern int MaxPing;
extern int af;
extern int reportwide;


void report_open(void) 
{
}


void report_close(void) 
{
  int i, j, at, max;
  ip_t *addr;
  char name[81];
  char buf[1024];
  char fmt[16];
  int len=0;
  int len_hosts = 33;
  struct hostent *host;

  if (reportwide)
  {
    // get the longest hostname
    len_hosts = strlen(LocalHostname);
    max = net_max();
    at  = net_min();
    for (; at < max; at++) {
      addr = net_addr(at);
      if( addrcmp( (void *) addr, (void *) &unspec_addr, af ) != 0 ) {
        host = dns ? addr2host( (void *) addr, af ) : NULL;
        if (host != NULL) {
          strncpy( name, host->h_name, (sizeof name) - 1 );
          name[ (sizeof name) - 1 ] = '\0'; 
        } else {
          snprintf(name, sizeof(name), "%s", strlongip( addr ) );
        }
        if (len_hosts < strlen(name)) {
          len_hosts = strlen(name);
        }
      }    
    }
  }
  
  snprintf( fmt, sizeof(fmt), "HOST: %%-%ds", len_hosts);
  snprintf(buf, sizeof(buf), fmt, LocalHostname);
  len = reportwide ? strlen(buf) : len_hosts;
  for( i=0; i<MAXFLD; i++ ) {
    j = fld_index[fld_active[i]];
    if (j < 0) continue;

    snprintf( fmt, sizeof(fmt), "%%%ds", data_fields[j].length );
    snprintf( buf + len, sizeof(buf), fmt, data_fields[j].title );
    len +=  data_fields[j].length;
  }
  printf("%s\n",buf);

  max = net_max();
  at  = net_min();
  for(; at < max; at++) {
    addr = net_addr(at);
    
    if( addrcmp( (void *) addr, (void *) &unspec_addr, af ) == 0 ) {
      sprintf(name, "???");
    } else {
      host = dns ? addr2host( (void *) addr, af ) : NULL;

      if (host != NULL) {
        strncpy( name, host->h_name, (sizeof name) - 1 );
        name[ (sizeof name) - 1 ] = '\0'; 
      } else {
        snprintf(name, sizeof(name), "%s", strlongip( addr ) );
      }
    }

    snprintf( fmt, sizeof(fmt), " %%2d. %%-%ds", len_hosts);
    snprintf(buf, sizeof(buf), fmt, at+1, name);
    len = reportwide ? strlen(buf) : len_hosts;  
    for( i=0; i<MAXFLD; i++ ) {
      j = fld_index[fld_active [i]];
      if (j < 0) continue;

      /* 1000.0 is a temporay hack for stats usec to ms, impacted net_loss. */
      if( index( data_fields[j].format, 'f' ) ) {
        snprintf( buf + len, sizeof(buf), data_fields[j].format,
		data_fields[j].net_xxx(at) /1000.0 );
      } else {
        snprintf( buf + len, sizeof(buf), data_fields[j].format,
		data_fields[j].net_xxx(at) );
      }
      len +=  data_fields[j].length;
    }
    printf("%s\n",buf);
  }
}


void txt_open(void)
{
}


void txt_close(void)
{ 
  report_close();
}



void xml_open(void)
{
}


void xml_close(void)
{
  int i, j, at, max;
  ip_t *addr;
  char name[81];
  struct hostent *host;

  printf("<MTR SRC=%s DST=%s", LocalHostname, Hostname);
  printf(" TOS=0x%X", tos);
  if(cpacketsize >= 0) {
    printf(" PSIZE=%d", cpacketsize);
  } else {
    printf(" PSIZE=rand(%d-%d)",MINPACKET, -cpacketsize);
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
    
    if( addrcmp( (void *) addr, (void *) &unspec_addr, af ) == 0 ) {
      sprintf(name, "???");
    } else {
      host = dns ? addr2host( (void *) addr, af ) : NULL;

      if (host != NULL) {
	 strncpy( name, host->h_name, (sizeof name) - 1 );
	 name[ (sizeof name) - 1 ] = '\0'; 
      } else {
	sprintf(name, "%s", strlongip( addr ) );
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


void csv_open(void)
{
}


void csv_close(void)
{
  int i, j, at, max;
  ip_t *addr;
  char name[81];
  struct hostent *host;

  /* Caption */
  printf("<SRC=%s DST=%s", LocalHostname, Hostname);
  printf(" TOS=0x%X", tos);
  if(cpacketsize >= 0) {
    printf(" PSIZE=%d", cpacketsize);
  } else {
    printf(" PSIZE=rand(%d-%d)",MINPACKET, -cpacketsize);
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
    
    if( addrcmp( (void *) addr, (void *) &unspec_addr, af ) == 0 ) {
      sprintf(name, "???");
    } else {
      host = dns ? addr2host( (void *) addr, af ) : NULL;

      if (host != NULL) {
	 strncpy( name, host->h_name, (sizeof name) - 1 );
	 name[ (sizeof name) - 1 ] = '\0'; 
      } else {
	sprintf(name, "%s", strlongip( addr ) );
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
