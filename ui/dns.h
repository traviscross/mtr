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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <config.h>
#include <netinet/in.h>
#include <resolv.h>

/*  Prototypes for dns.c  */

extern void dns_open(
    void);
extern int dns_waitfd(
    void);
extern void dns_ack(
    struct mtr_ctl *ctl);
#ifdef ENABLE_IPV6
extern int dns_waitfd6(
    void);
extern void dns_ack6(
    void);
#endif

extern char *dns_lookup(
    struct mtr_ctl *ctl,
    ip_t * address);
extern char *dns_lookup2(
    struct mtr_ctl *ctl,
    ip_t * address);
extern char *strlongip(
    sa_family_t family,
    ip_t * ip);

extern void addr2ip6arpa(
    ip_t * ip,
    char *buf);
extern struct hostent *addr2host(
    const char *addr,
    int type);
