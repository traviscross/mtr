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

/*  Prototypes for functions in net.c  */
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

int net_preopen(void);
int net_selectsocket(void);
int net_open(struct hostent *host);
void net_reopen(struct hostent *address);
int net_set_interfaceaddress (char *InterfaceAddress); 
void net_reset(void);
void net_close(void);
int net_waitfd(void);
void net_process_return(void);

int net_max(void);
int net_min(void);
int net_last(int at);
ip_t * net_addr(int at);
int net_loss(int at);
int net_drop(int at);
int net_last(int at);
int net_best(int at);
int net_worst(int at);
int net_avg(int at);
int net_gmean(int at);
int net_stdev(int at);
int net_jitter(int at);
int net_jworst(int at);
int net_javg(int at);
int net_jinta(int at);
ip_t * net_addrs(int at, int i);
char *net_localaddr(void); 

int net_send_batch(void);
void net_end_transit(void);

int calc_deltatime (float WaitTime);


/* Added by Brian Casey, December 1997 bcasey@imagiware.com*/
int net_returned(int at);
int net_xmit(int at);
int net_transit(int at);

int net_up(int at);

#define SAVED_PINGS 200
int* net_saved_pings(int at);
void net_save_xmit(int at);
void net_save_return(int at, int seq, int ms);
int net_duplicate(int at, int seq);

void sockaddrtop( struct sockaddr * saddr, char * strptr, size_t len );
int addrcmp( char * a, char * b, int af );
void addrcpy( char * a, char * b, int af );

#define MAXPATH 8
#define MaxHost 256
#define MinSequence 33000
#define MaxSequence 65536
#define MinPort 1024

#define MAXPACKET 4470		/* largest test packet size */
#define MINPACKET 28		/* 20 bytes IP header and 8 bytes ICMP or UDP */

/* stuff used by display such as report, curses... --Min */
#define MAXFLD 20		/* max stats fields to display */

#if defined (__STDC__) && __STDC__
#define CONST const
#else
#define CONST /* */
#endif


/* XXX This doesn't really belong in this header file, but as the
   right c-files include it, it will have to do for now. -- REW */

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

ip_t unspec_addr;
