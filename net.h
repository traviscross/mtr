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

static struct fields data_fields[MAXFLD] = {
  /* Remark, Header, Format, Width, CallBackFunc */
  { "<sp>: Space between fields", " ",  " ",        1, &net_drop  },   /* 0 */
  { "L: Loss Ratio",          "Loss%",  " %4.1f%%", 6, &net_loss  },   /* 1 */
  { "D: Dropped Packets",     "Drop",   " %4d",     5, &net_drop  },   /* 2 */
  { "R: Received Packets",    "Rcv",    " %5d",     6, &net_returned}, /* 3 */
  { "S: Sent Packets",        "Snt",    " %5d",     6, &net_xmit  },   /* 4 */
  { "N: Newest RTT(ms)",      "Last",   " %5.1f",   6, &net_last  },   /* 5 */
  { "B: Min/Best RTT(ms)",    "Best",   " %5.1f",   6, &net_best  },   /* 6 */
  { "A: Average RTT(ms)",     "Avg",    " %5.1f",   6, &net_avg   },   /* 7 */
  { "W: Max/Worst RTT(ms)",   "Wrst",   " %5.1f",   6, &net_worst },   /* 8 */
  { "V: Standard Deviation",  "StDev",  " %5.1f",   6, &net_stdev },   /* 9 */
  { "G: Geometric Mean",      "Gmean",  " %5.1f",   6, &net_gmean },   /* 10 */
  { "J: Current Jitter",      "Jttr",   " %4.1f",   5, &net_jitter},   /* 11 */
  { "M: Jitter Mean/Avg.",    "Javg",   " %4.1f",   5, &net_javg  },   /* 12 */
  { "X: Worst Jitter",        "Jmax",   " %4.1f",   5, &net_jworst},   /* 13 */
  { "I: Interarrival Jitter", "Jint",   " %4.1f",   5, &net_jinta },   /* 14 */
  { 0, 0, 0, 0, 0 }
};

/* keys: the value in the array is the index number in data_fields[] */
static int fld_index[] = {
   0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,           /* ' ', 0,1..9 */
   7,  6, -1,  2, -1, -1, 10, -1, 14, 11, -1,  1, 12,   /* A..M */
   5, -1, -1, -1,  3,  4, -1, -1,  9,  8, 13, -1, -1,   /* N..Z */
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,   /* a..m */
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,   /* n..z */
  -1
};
