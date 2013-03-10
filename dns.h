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
#include <netinet/in.h>
#include <resolv.h>

/*  Prototypes for dns.c  */

void dns_open(void);
int dns_waitfd(void);
void dns_ack(void);
#ifdef ENABLE_IPV6
int dns_waitfd6(void);
void dns_ack6(void);
#ifdef NEED_RES_STATE_EXT
/* __res_state_ext is missing on many (most?) BSD systems */
struct __res_state_ext {
	union res_sockaddr_union nsaddrs[MAXNS];
	struct sort_list {
		int     af;
		union {
			struct in_addr  ina;
			struct in6_addr in6a;
		} addr, mask;
	} sort_list[MAXRESOLVSORT];
	char nsuffix[64];
	char nsuffix2[64];
};
#endif
#endif

void dns_events(double *sinterval);
char *dns_lookup(ip_t * address);
char *dns_lookup2(ip_t * address);
struct hostent * dns_forward(const char *name);
char *strlongip(ip_t * ip);

void addr2ip6arpa( ip_t * ip, char * buf );
struct hostent *addr2host( const char *addr, int type );
