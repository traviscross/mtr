/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

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

#include <config.h>
#include <sys/types.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "mtr.h"
#include "report.h"
#include "net.h"
#include "dns.h"
#ifndef NO_IPINFO
#include "asn.h"
#endif

#define MAXLOADBAL 5

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


char *get_time_string (void) 
{
  time_t now; 
  char *t;
  now = time (NULL);
  t = ctime (&now);
  t [ strlen (t) -1] = 0; // remove the trailing newline
  return t;
}

void report_open(void)
{
  printf ("Start: %s\n", get_time_string ());
}

static size_t snprint_addr(char *dst, size_t dst_len, ip_t *addr)
{
  if(addrcmp((void *) addr, (void *) &unspec_addr, af)) {
    struct hostent *host = dns ? addr2host((void *) addr, af) : NULL;
    if (!host) return snprintf(dst, dst_len, "%s", strlongip(addr));
    else if (dns && show_ips)
      return snprintf(dst, dst_len, "%s (%s)", host->h_name, strlongip(addr));
    else return snprintf(dst, dst_len, "%s", host->h_name);
  } else return snprintf(dst, dst_len, "%s", "???");
}


#ifndef NO_IPINFO
void print_mpls(struct mplslen *mpls) {
  int k;
  for (k=0; k < mpls->labels; k++)
    printf("       [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mpls->label[k], mpls->exp[k], mpls->s[k], mpls->ttl[k]);
}
#endif

void report_close(void) 
{
  int i, j, at, max, z, w;
  struct mplslen *mpls, *mplss;
  ip_t *addr;
  ip_t *addr2 = NULL;  
  char name[81];
  char buf[1024];
  char fmt[16];
  int len=0;
  int len_hosts = 33;

  if (reportwide)
  {
    // get the longest hostname
    len_hosts = strlen(LocalHostname);
    max = net_max();
    at  = net_min();
    for (; at < max; at++) {
      int nlen;
      addr = net_addr(at);
      if ((nlen = snprint_addr(name, sizeof(name), addr)))
        if (len_hosts < nlen)
          len_hosts = nlen;
    }
  }
  
#ifndef NO_IPINFO
  int len_tmp = len_hosts;
  if (ipinfo_no >= 0) {
    ipinfo_no %= iiwidth_len;
    if (reportwide) {
      len_hosts++;    // space
      len_tmp   += get_iiwidth();
      if (!ipinfo_no)
        len_tmp += 2; // align header: AS
    }
  }
  snprintf( fmt, sizeof(fmt), "HOST: %%-%ds", len_tmp);
#else
  snprintf( fmt, sizeof(fmt), "HOST: %%-%ds", len_hosts);
#endif
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
    mpls = net_mpls(at);
    snprint_addr(name, sizeof(name), addr);

#ifndef NO_IPINFO
    if (is_printii()) {
      snprintf(fmt, sizeof(fmt), " %%2d. %%s%%-%ds", len_hosts);
      snprintf(buf, sizeof(buf), fmt, at+1, fmt_ipinfo(addr), name);
    } else {
#endif
    snprintf( fmt, sizeof(fmt), " %%2d.|-- %%-%ds", len_hosts);
    snprintf(buf, sizeof(buf), fmt, at+1, name);
#ifndef NO_IPINFO
    }
#endif
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

    /* This feature shows 'loadbalances' on routes */

    /* z is starting at 1 because addrs[0] is the same that addr */
    for (z = 1; z < MAXPATH ; z++) {
      addr2 = net_addrs(at, z);
      mplss = net_mplss(at, z);
      int found = 0;
      if ((addrcmp ((void *) &unspec_addr, (void *) addr2, af)) == 0)
        break;
      for (w = 0; w < z; w++)
        /* Ok... checking if there are ips repeated on same hop */
        if ((addrcmp ((void *) addr2, (void *) net_addrs (at,w), af)) == 0) {
           found = 1;
           break;
        }   

      if (!found) {
  
#ifndef NO_IPINFO
        if (is_printii()) {
          if (mpls->labels && z == 1 && enablempls)
            print_mpls(mpls);
          snprint_addr(name, sizeof(name), addr2);
          printf("     %s%s\n", fmt_ipinfo(addr2), name);
          if (enablempls)
            print_mpls(mplss);
        } else {
#else
        int k;
        if (mpls->labels && z == 1 && enablempls) {
          for (k=0; k < mpls->labels; k++) {
            printf("    |  |+-- [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mpls->label[k], mpls->exp[k], mpls->s[k], mpls->ttl[k]);
          }
        }

        if (z == 1) {
          printf ("    |  `|-- %s\n", strlongip(addr2));
          for (k=0; k < mplss->labels && enablempls; k++) {
            printf("    |   +-- [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mplss->label[k], mplss->exp[k], mplss->s[k], mplss->ttl[k]);
          }
        } else {
          printf ("    |   |-- %s\n", strlongip(addr2));
          for (k=0; k < mplss->labels && enablempls; k++) {
            printf("    |   +-- [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mplss->label[k], mplss->exp[k], mplss->s[k], mplss->ttl[k]);
          }
        }
#endif
#ifndef NO_IPINFO
        }
#endif
      }
    }

    /* No multipath */
#ifndef NO_IPINFO
    if (is_printii()) {
      if (mpls->labels && z == 1 && enablempls)
        print_mpls(mpls);
    } else {
#else
    if(mpls->labels && z == 1 && enablempls) {
      int k;
      for (k=0; k < mpls->labels; k++) {
        printf("    |   +-- [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mpls->label[k], mpls->exp[k], mpls->s[k], mpls->ttl[k]);
      }
    }
#endif
#ifndef NO_IPINFO
    }
#endif
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
    snprint_addr(name, sizeof(name), addr);

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

  for( i=0; i<MAXFLD; i++ ) {
      j = fld_index[fld_active[i]];
      if (j < 0) continue; 
  }

  max = net_max();
  at  = net_min();
  for(; at < max; at++) {
    addr = net_addr(at);
    snprint_addr(name, sizeof(name), addr);

    printf("MTR.0;%s;%d;%s", Hostname, at+1, name);
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
