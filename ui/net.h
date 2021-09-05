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

/*  Prototypes for functions in net.c  */
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#endif

#include <stdint.h>

#include "mtr.h"

extern int net_open(
    struct mtr_ctl *ctl,
    struct addrinfo *res);
extern void net_reopen(
    struct mtr_ctl *ctl,
    struct addrinfo *res);
extern void net_reset(
    struct mtr_ctl *ctl);
extern void net_close(
    void);
extern int net_waitfd(
    void);
extern void net_process_return(
    struct mtr_ctl *ctl);
extern void net_harvest_fds(
    struct mtr_ctl *ctl);

extern int net_max(
    struct mtr_ctl *ctl);
extern int net_min(
    struct mtr_ctl *ctl);
extern int net_last(
    int at);
extern ip_t *net_addr(
    int at);
extern int net_err(
    int at);
extern struct mplslen *net_mpls(
    int at);
extern struct mplslen *net_mplss(
    int,
    int);
extern int net_loss(
    int at);
extern int net_drop(
    int at);
extern int net_best(
    int at);
extern int net_worst(
    int at);
extern int net_avg(
    int at);
extern int net_gmean(
    int at);
extern int net_stdev(
    int at);
extern int net_jitter(
    int at);
extern int net_jworst(
    int at);
extern int net_javg(
    int at);
extern int net_jinta(
    int at);
extern ip_t *net_addrs(
    int at,
    int i);
extern char *net_localaddr(
    void);
extern char *net_remoteaddr(
    void);

extern int net_send_batch(
    struct mtr_ctl *ctl);
extern void net_end_transit(
    void);

extern int calc_deltatime(
    float WaitTime);

extern int net_returned(
    int at);
extern int net_xmit(
    int at);

extern int net_up(
    int at);

extern int *net_saved_pings(
    int at);
extern void net_save_xmit(
    int at);
extern void net_save_return(
    int at,
    int seq,
    int ms);

extern int addrcmp(
    void *a,
    void *b,
    int af);

extern void net_add_fds(
    fd_set * writefd,
    int *maxfd);
