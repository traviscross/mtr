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

int net_preopen();
int net_open(int address);
void net_reopen(int address);
void net_reset();
void net_close();
int net_waitfd();
void net_process_return();

int net_max(void);
int net_min(void);
int net_last(int at);
int net_addr(int at);
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
int net_addrs(int at, int i);


int net_send_batch();
void net_end_transit();

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

#define MAXPATH 8
#define MaxHost 256
#define MaxSequence 65536

#define MAXPACKET 4470		/* largest test ICMP packet size */
#define MINPACKET 28		/* 20 bytes IP header and 8 bytes ICMP */

/* stuff used by display such as report, curses... --Min */
#define MAXFLD 20		/* max stats fields to display */

#if defined (__STDC__) && __STDC__
#define CONST const
#else
#define CONST /* */
#endif


/* dynamic field drawing */
struct fields {
  CONST char *descr;
  CONST char *title;
  CONST char *format;
  int length;
  int (*net_xxx)();
};

extern struct fields data_fields[MAXFLD];


/* keys: the value in the array is the index number in data_fields[] */
extern  int fld_index[];
