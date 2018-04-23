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

#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif
#include <errno.h>

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
#include <ares.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>
#include <syslog.h>

#include "mtr.h"
#include "asn.h"
#include "utils.h"
#include "display.h"

/* #define IIDEBUG */
#ifdef IIDEBUG
#include <syslog.h>
#define DEB_syslog syslog
#else
#define DEB_syslog(...) do {} while (0)
#endif

#define IIHASH_HI   128
#define ITEMSMAX    15
#define ITEMSEP '|'
#define NAMELEN 127
#define UNKN    "???"
#define SEMPATH "sem"

typedef char *items_t[ITEMSMAX + 1];
struct comparm {
    struct mtr_ctl *ctl;
    char key[NAMELEN];
};

static int iihash = 0;
static int loopmode = 0;    // mark DisplayCurses and DisplayGTK
static pthread_t tid;
static ares_channel channel;
static char syncstr[20];
static char unknown_txt[10] = {UNKN};
static items_t items_a;
static sem_t sem;
static volatile sig_atomic_t sigstat = 0;
/* items width: ASN, Route, Country, Registry, Allocated */
static const int iiwidth[] = { 7, 19, 4, 8, 11 };       /* item len + space */


static char *split_txtrec(
    struct mtr_ctl *ctl,
    char *txt_rec,
    items_t **p_items)
{
    char *prev;
    char *next;
    int i = 0, j;
    items_t *items = &items_a;

    if (!txt_rec)
        return NULL;
    if (iihash) {
        if (!(items = malloc(sizeof(*items)))) {
            free(txt_rec);
            return NULL;
        }
    }

    prev = txt_rec;

    while ((next = strchr(prev, ITEMSEP)) && (i < ITEMSMAX)) {
        *next = '\0';
        next++;
        (*items)[i] = trim(prev, ITEMSEP);
        prev = next;
        i++;
    }
    (*items)[i] = trim(prev, ITEMSEP);

    if (i < ITEMSMAX)
        i++;
    for (j = i; j <= ITEMSMAX; j++)
        (*items)[j] = NULL;

    *p_items = items;
    if (i > ctl->ipinfo_max)
        ctl->ipinfo_max = i;
    if (ctl->ipinfo_no >= i) {
        return (*items)[0];
    } else {
        return (*items)[ctl->ipinfo_no];
    }
}

static void query_callback (
    void* arg,
    int status,
    int timeouts,
    unsigned char *abuf,
    int aslen)
{
    struct ares_txt_reply *txt_out = NULL;
    struct comparm *parm = (struct comparm *)arg;
    items_t *items_tmp = NULL;
    char *retstr = NULL;
    ENTRY item;

    if (ARES_SUCCESS != ares_parse_txt_reply(abuf, aslen, &txt_out)) {
        retstr = split_txtrec(parm->ctl, unknown_txt, &items_tmp);
    } else {
        retstr = split_txtrec(parm->ctl, txt_out->txt, &items_tmp);
    }
    strncpy(syncstr, retstr, sizeof(syncstr)-1);

    if (retstr && iihash) {
        if ((item.key = xstrdup(parm->key))) {
            item.data = (void *) items_tmp;
            hsearch(item, ENTER);
            DEB_syslog(LOG_INFO, "Insert into hash: %s", parm->key);
        }
    } else if (iihash) {
        free(items_tmp);
    }

    /*  cannot free, hash use it!
    if (txt_out) {
        ares_free_data(txt_out);
    }*/

    free(parm);
}

void *wait_loop(
    void *arg)
{
    int nfds;
    fd_set readers;
    struct timeval tv;
    ares_channel channel = (ares_channel)arg;

    while (1) {
        if (sigstat == 1)
            break;

        FD_ZERO(&readers);
        nfds = ares_fds(channel, &readers, NULL);
        if (nfds == 0) {
            if (!loopmode) {
                break;
            } else {
                sem_wait(&sem);
                continue;
            }
        }
        if (select(nfds, &readers, NULL, NULL,
                    ares_timeout(channel, NULL, &tv)) > 0) {
            ares_process(channel, &readers, NULL);
        }
     }

     return NULL;
}

static void ipinfo_lookup(
    struct mtr_ctl *ctl,
    const char *domain,
    struct comparm *parm)
{
    if (!loopmode) {
        if(ares_init(&channel) != ARES_SUCCESS) {
            error(0, 0, "ares_init failed");
            free(parm);
            return;
        }
        memset(syncstr, 0, sizeof(syncstr));
    }

    ares_query(channel, domain, C_IN, T_TXT, query_callback, parm);
    if (loopmode == 1) {
        sem_post(&sem);
    }

    if (!loopmode) {
        wait_loop(channel);
    }
}

#ifdef ENABLE_IPV6
/* from dns.c:addr2ip6arpa() */
static void reverse_host6(
    struct in6_addr *addr,
    char *buff,
    int buff_length)
{
    int i;
    char *b = buff;
    for (i = (sizeof(*addr) / 2 - 1); i >= 0; i--, b += 4)      /* 64b portion */
        snprintf(b, buff_length,
                 "%x.%x.", addr->s6_addr[i] & 0xf, addr->s6_addr[i] >> 4);

    buff[strlen(buff) - 1] = '\0';
}
#endif

static char *get_ipinfo(
    struct mtr_ctl *ctl,
    ip_t * addr)
{
    char key[NAMELEN];
    char lookup_key[NAMELEN];
    char *val = NULL;
    struct comparm *parm;
    ENTRY item;

    if (!addr)
        return NULL;

    if (ctl->af == AF_INET6) {
#ifdef ENABLE_IPV6
        reverse_host6(addr, key, NAMELEN);
        if (snprintf(lookup_key, NAMELEN, "%s.origin6.asn.cymru.com", key)
            >= NAMELEN)
            return NULL;
#else
        return NULL;
#endif
    } else {
        unsigned char buff[4];
        memcpy(buff, addr, 4);
        if (snprintf
            (key, NAMELEN, "%d.%d.%d.%d", buff[3], buff[2], buff[1],
             buff[0]) >= NAMELEN)
            return NULL;
        if (snprintf(lookup_key, NAMELEN, "%s.origin.asn.cymru.com", key)
            >= NAMELEN)
            return NULL;
    }

    if (iihash) {
        ENTRY *found_item;

        DEB_syslog(LOG_INFO, ">> Search: %s", key);
        item.key = key;
        if ((found_item = hsearch(item, FIND))) {
            if (!(val = (*((items_t *) found_item->data))[ctl->ipinfo_no]))
                val = (*((items_t *) found_item->data))[0];
            DEB_syslog(LOG_INFO, "Found (hashed): %s", val);
        }
    }

    if (!val) {
        parm = (struct comparm *)malloc(sizeof(struct comparm));
        if (parm == NULL)
            return NULL;
        parm->ctl = ctl;
        strncpy(parm->key, key, sizeof(parm->key)-1);
        ipinfo_lookup(ctl, lookup_key, parm);
        if (!loopmode) {
            return syncstr;
        }
    }

    return val;
}

ATTRIBUTE_CONST size_t get_iiwidth_len(
    void)
{
    return (sizeof(iiwidth) / sizeof((iiwidth)[0]));
}

ATTRIBUTE_CONST int get_iiwidth(
    int ipinfo_no)
{
    static const int len = (sizeof(iiwidth) / sizeof((iiwidth)[0]));

    if (ipinfo_no < len)
        return iiwidth[ipinfo_no];
    return iiwidth[ipinfo_no % len];
}

char *fmt_ipinfo(
    struct mtr_ctl *ctl,
    ip_t * addr)
{
    char fmt[8];
    static char fmtinfo[32];
    char *ipinfo = NULL;

    ipinfo = get_ipinfo(ctl, addr);
    snprintf(fmt, sizeof(fmt), "%s%%-%ds", ctl->ipinfo_no ? "" : "AS",
             get_iiwidth(ctl->ipinfo_no));
    snprintf(fmtinfo, sizeof(fmtinfo), fmt, ipinfo ? ipinfo : UNKN);

    return fmtinfo;
}

int is_printii(
    struct mtr_ctl *ctl)
{
    return (ctl->ipinfo_no >= 0);
}

void asn_open(
    struct mtr_ctl *ctl)
{
    #ifdef HAVE_CURSES
    if (ctl->DisplayMode == DisplayCurses) {
        loopmode = 1;
    }
    #endif
    #ifdef HAVE_GTK
    if (ctl->DisplayMode == DisplayGTK) {
        loopmode = 1;
    }
    #endif

    if (ctl->ipinfo_no >= 0) {
        DEB_syslog(LOG_INFO, "hcreate(%d)", IIHASH_HI);
        if (!(iihash = hcreate(IIHASH_HI)))
            error(0, errno, "ipinfo hash");

        if(ares_init(&channel) != ARES_SUCCESS) {
            error(0, 0, "ares_init failed");
            return;
        }

        if (sem_open(SEMPATH, O_CREAT|O_RDWR, 0666, 0) == SEM_FAILED) {
            error(0, 0, "sem_open failed");
            return ;
        }

        if (pthread_create(&tid, NULL, wait_loop, channel)) {
            error(0, 0, "pthread_create failed");
            tid = pthread_self();
        }
        pthread_detach(tid);
    }
}

void asn_close(
    struct mtr_ctl *ctl)
{
    if ((ctl->ipinfo_no >= 0) && iihash) {
        DEB_syslog(LOG_INFO, "hdestroy()");
        hdestroy();
        iihash = 0;
    }

    if (ctl->ipinfo_no >= 0) {
        ares_destroy(channel);
        if (pthread_equal(tid, pthread_self()) == 0) {
            sigstat = 1;
            sem_post(&sem);
        }
        sem_close(&sem);
        sem_unlink(SEMPATH);
    }
}
