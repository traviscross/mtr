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

/*
    Copyright (C) 2010 by Roderick Groesbeek <mtr@roderick.triple-it.nl>
    Released under GPL, as above.
*/

#include "asn.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#ifndef __APPLE__
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>


int  PrintAS = 0;
#ifndef NO_GLIB
GHashTable * ashash = NULL;
#endif

char *asn_lookup(const char *domain)
{
    unsigned char answer[PACKETSZ],  *pt;
    char host[128];
    char *txt;
    int len, exp, size, txtlen, type;


    if(res_init() < 0) {
        fprintf(stderr,"@res_init failed\n");
        return NULL;
    }

    memset(answer, 0, PACKETSZ);
    if((len = res_query(domain, C_IN, T_TXT, answer, PACKETSZ)) < 0) {
        return "-1";
    }

    pt = answer + sizeof(HEADER);

    if((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0) {
        printf("@dn_expand failed\n"); return NULL;
    }

    pt += exp;

    GETSHORT(type, pt);
    if(type != T_TXT) {
        printf("@Broken DNS reply.\n"); return NULL;
    }

    pt += INT16SZ; /* class */

    if((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0) {
        printf("@second dn_expand failed\n"); return NULL;
    }

    pt += exp;
    GETSHORT(type, pt);
    if(type != T_TXT) {
        printf("@Not a TXT record\n"); return NULL;
    }

    pt += INT16SZ; /* class */
    GETSHORT(size, pt);
    txtlen = *pt;


    if(txtlen >= size || !txtlen) {
        printf("@Broken TXT record (txtlen = %d, size = %d)\n", txtlen, size); return NULL;
    }

    if(!(txt = malloc(txtlen + 1)))
        return NULL;

    pt++;
    strncpy(txt, (char*) pt, txtlen);
    txt[txtlen] = 0;

    return txt;
}




