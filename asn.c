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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef __APPLE__
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
#include <search.h>

#include "config.h"
#include "mtr.h"
#include "asn.h"

/*
#ifndef IIDEBUG
#define IIDEBUG
#include <syslog.h>
#endif
*/

#define IIHASH_HI	128
#define ITEMSMAX	15
#define ITEMSEP	'|'
#define NAMELEN	127
#define UNKN	"???"

int  ipinfo_no = -1;
int  ipinfo_max = -1;
int  iihash = 0;
char fmtinfo[32];
extern int af;                  /* address family of remote target */

// items width: ASN, Route, Country, Registry, Allocated 
int iiwidth[] = { 6, 19, 4, 8, 11};	// item len + space
int iiwidth_len = sizeof(iiwidth)/sizeof((iiwidth)[0]);

typedef char* items_t[ITEMSMAX + 1];
items_t items_a;		// without hash: items
char txtrec[NAMELEN + 1];	// without hash: txtrec
items_t* items = &items_a;


char *ipinfo_lookup(const char *domain) {
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
#ifdef IIDEBUG
        if (iihash)
            syslog(LOG_INFO, "Malloc-txt: %s", UNKN);
#endif
        return (iihash)?strdup(UNKN):UNKN;
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
    pt += INT32SZ; /* ttl */
    GETSHORT(size, pt);
    txtlen = *pt;


    if(txtlen >= size || !txtlen) {
        printf("@Broken TXT record (txtlen = %d, size = %d)\n", txtlen, size); return NULL;
    }

    if (txtlen > NAMELEN)
        txtlen = NAMELEN;

    if (iihash) {
        if (!(txt = malloc(txtlen + 1)))
            return NULL;
    } else
        txt = (char*)txtrec;

    pt++;
    strncpy(txt, (char*) pt, txtlen);
    txt[txtlen] = 0;

#ifdef IIDEBUG
    if (iihash)
        syslog(LOG_INFO, "Malloc-txt(%p): %s", txt, txt);
#endif

    return txt;
}

char* trimsep(char *s) {
    int l;
    char *p = s;
    while (*p == ' ' || *p == ITEMSEP)
        *p++ = '\0';
    for (l = strlen(p)-1; p[l] == ' ' || p[l] == ITEMSEP; l--)
        p[l] = '\0';
    return p;
}

// originX.asn.cymru.com txtrec:    ASN | Route | Country | Registry | Allocated
char* split_txtrec(char *txtrec) {
    if (!txtrec)
	return NULL;
    if (iihash) {
#ifdef IIDEBUG
        syslog(LOG_INFO, "Malloc-tbl: %s", txtrec);
#endif
        if (!(items = malloc(sizeof(*items)))) {
#ifdef IIDEBUG
            syslog(LOG_INFO, "Free-txt(%p)", txtrec);
#endif
            free(txtrec);
            return NULL;
        }
    }

    char* prev = (*items)[0] = trimsep(txtrec);
    char* next;
    int i = 0, j;

    while ((next = strchr(prev, ITEMSEP)) && (i < ITEMSMAX)) {
        *next++ = '\0';
        (*items)[i++] = trimsep(prev);
        (*items)[i] = prev = trimsep(next);
    }
    if (i < ITEMSMAX)
        i++;
    for (j = i;  j <= ITEMSMAX; j++)
        (*items)[j] = NULL;

    if (i > ipinfo_max)
        ipinfo_max = i;
    if (ipinfo_no >= i) {
        if (ipinfo_no >= ipinfo_max)
            ipinfo_no = 0;
	return (*items)[0];
    } else
	return (*items)[ipinfo_no];
}

#ifdef ENABLE_IPV6
// from dns.c:addr2ip6arpa()
void reverse_host6(struct in6_addr *addr, char *buff) {
    int i;
    char *b = buff;
    for (i=(sizeof(*addr)/2-1); i>=0; i--, b+=4) // 64b portion
        sprintf(b, "%x.%x.", addr->s6_addr[i] & 0xf, addr->s6_addr[i] >> 4);
    buff[strlen(buff) - 1] = '\0';
}
#endif

char *get_ipinfo(ip_t *addr) {
    if (!addr)
        return NULL;

    char key[NAMELEN];
    char lookup_key[NAMELEN];

    if (af == AF_INET6) {
#ifdef ENABLE_IPV6
        reverse_host6(addr, key);
        if (snprintf(lookup_key, NAMELEN, "%s.origin6.asn.cymru.com", key) >= NAMELEN)
            return NULL;
#else
	return NULL;
#endif
    } else {
        unsigned char buff[4];
        memcpy(buff, addr, 4);
        if (snprintf(key, NAMELEN, "%d.%d.%d.%d", buff[3], buff[2], buff[1], buff[0]) >= NAMELEN)
            return NULL;
        if (snprintf(lookup_key, NAMELEN, "%s.origin.asn.cymru.com", key) >= NAMELEN)
            return NULL;
    }

    char *val = NULL;
    ENTRY item;

    if (iihash) {
#ifdef IIDEBUG
        syslog(LOG_INFO, ">> Search: %s", key);
#endif
        item.key = key;;
        ENTRY *found_item;
        if ((found_item = hsearch(item, FIND))) {
            if (!(val = (*((items_t*)found_item->data))[ipinfo_no]))
                val = (*((items_t*)found_item->data))[0];
#ifdef IIDEBUG
        syslog(LOG_INFO, "Found (hashed): %s", val);
#endif
        }
    }

    if (!val) {
#ifdef IIDEBUG
        syslog(LOG_INFO, "Lookup: %s", key);
#endif
        if ((val = split_txtrec(ipinfo_lookup(lookup_key)))) {
#ifdef IIDEBUG
            syslog(LOG_INFO, "Looked up: %s", key);
#endif
            if (iihash)
                if ((item.key = strdup(key))) {
                    item.data = items;
                    hsearch(item, ENTER);
#ifdef IIDEBUG
                    syslog(LOG_INFO, "Insert into hash: %s", key);
#endif
                }
        }
    }

    return val;
}

int get_iiwidth(void) {
    return (ipinfo_no < iiwidth_len) ? iiwidth[ipinfo_no] : iiwidth[ipinfo_no % iiwidth_len];
}

char *fmt_ipinfo(ip_t *addr) {
    char *ipinfo = get_ipinfo(addr);
    char fmt[8];
    snprintf(fmt, sizeof(fmt), "%s%%-%ds", ipinfo_no?"":"AS", get_iiwidth());
    snprintf(fmtinfo, sizeof(fmtinfo), fmt, ipinfo?ipinfo:UNKN);
    return fmtinfo;
}

int is_printii(void) {
    return ((ipinfo_no >= 0) && (ipinfo_no != ipinfo_max));
}

void asn_open(void) {
    if (ipinfo_no >= 0) {
#ifdef IIDEBUG
        syslog(LOG_INFO, "hcreate(%d)", IIHASH_HI);
#endif
        if (!(iihash = hcreate(IIHASH_HI)))
            perror("ipinfo hash");
    }
}

void asn_close(void) {
    if (iihash) {
#ifdef IIDEBUG
        syslog(LOG_INFO, "hdestroy()");
#endif
        hdestroy();
        iihash = 0;
    }
}

