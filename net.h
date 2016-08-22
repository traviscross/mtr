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

/*  Prototypes for functions in net.c  */
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

extern int net_preopen(void);
extern int net_selectsocket(void);
extern int net_open(struct hostent *host);
extern void net_reopen(struct hostent *address);
extern int net_set_interfaceaddress (char *InterfaceAddress); 
extern void net_reset(void);
extern void net_close(void);
extern int net_waitfd(void);
extern void net_process_return(void);
extern void net_harvest_fds(void);

extern int net_max(void);
extern int net_min(void);
extern int net_last(int at);
extern ip_t * net_addr(int at);
extern void * net_mpls(int at);
extern void * net_mplss(int, int);
extern int net_loss(int at);
extern int net_drop(int at);
extern int net_best(int at);
extern int net_worst(int at);
extern int net_avg(int at);
extern int net_gmean(int at);
extern int net_stdev(int at);
extern int net_jitter(int at);
extern int net_jworst(int at);
extern int net_javg(int at);
extern int net_jinta(int at);
extern ip_t * net_addrs(int at, int i);
extern char *net_localaddr(void); 

extern int net_send_batch(void);
extern void net_end_transit(void);

extern int calc_deltatime (float WaitTime);

extern int net_returned(int at);
extern int net_xmit(int at);

extern int net_up(int at);

#define SAVED_PINGS 200
extern int* net_saved_pings(int at);
extern void net_save_xmit(int at);
extern void net_save_return(int at, int seq, int ms);

extern int addrcmp( char * a, char * b, int af );
extern void addrcpy( char * a, char * b, int af );

extern void net_add_fds(fd_set *writefd, int *maxfd);
extern void net_process_fds(fd_set *writefd);

#define MAXPATH 8
#define MaxHost 256
#define MinSequence 33000
#define MaxSequence 65536
#define MinPort 1024
#define MaxPort 65535

#define MAXPACKET 4470		/* largest test packet size */
#define MINPACKET 28		/* 20 bytes IP header and 8 bytes ICMP or UDP */
#define MAXLABELS 8 		/* http://kb.juniper.net/KB2190 (+ 3 just in case) */

/* stuff used by display such as report, curses... */
#define MAXFLD 20		/* max stats fields to display */

#if defined (__STDC__) && __STDC__
#define CONST const
#else
#define CONST /* */
#endif


/* XXX This doesn't really belong in this header file, but as the
   right c-files include it, it will have to do for now. */

/* dynamic field drawing */
struct fields {
  CONST unsigned char key;
  CONST char *descr;
  CONST char *title;
  CONST char *format;
  int length;
  int (*net_xxx)();
};

extern struct fields data_fields[MAXFLD];


/* keys: the value in the array is the index number in data_fields[] */
extern int fld_index[];
extern unsigned char fld_active[];
extern char available_options[];

extern ip_t unspec_addr;

/* MPLS label object */
struct mplslen {
  unsigned long label[MAXLABELS]; /* label value */
  uint8 exp[MAXLABELS]; /* experimental bits */
  uint8 ttl[MAXLABELS]; /* MPLS TTL */
  char s[MAXLABELS]; /* bottom of stack */
  char labels; /* how many labels did we get? */
};

#ifdef IPPROTO_SCTP
    #define HAS_SCTP
#endif


