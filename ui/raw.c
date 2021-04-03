/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1998  R.E.Wolff@BitWizard.nl

    raw.c -- raw output (for logging for later analysis)

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

#include "config.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mtr.h"
#include "raw.h"
#include "net.h"
#include "dns.h"


/* Log an echo request, or a "ping" */
void raw_rawxmit(
    int host,
    int seq)
{
    printf("x %d %d\n", host, seq);
    fflush(stdout);
}

/* Log an echo reply, or a "pong" */
void raw_rawping(
    struct mtr_ctl *ctl,
    int host,
    int msec,
    int seq)
{
    static int havename[MaxHost];
    char *name;

    if (ctl->dns && !havename[host]) {
        name = dns_lookup2(ctl, net_addr(host));
        if (name) {
            havename[host]++;
            printf("d %d %s\n", host, name);
        }
    }
    printf("p %d %d %d\n", host, msec, seq);
    fflush(stdout);
}

void raw_rawhost(
    struct mtr_ctl *ctl,
    int host,
    ip_t *ip_addr,
    struct mplslen *mpls)
{
    printf("h %d %s\n", host, strlongip(ctl->af, ip_addr));
    if (ctl->enablempls) {
        int k;
        for (k = 0; k < mpls->labels; k++)
            printf("m %d %lu %u %u %u\n",
                   host, mpls->label[k], mpls->tc[k], mpls->s[k], mpls->ttl[k]);
    }

    fflush(stdout);
}
