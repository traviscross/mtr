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

#include <config.h>
#include <strings.h>
#include <unistd.h>

#ifndef NO_CURSES
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* MacOSX may need this before scoket.h...*/
#if defined(HAVE_SYS_TYPES_H)
#include <sys/types.h>
#else
/* If a system doesn't have sys/types.h, lets hope that time_t is an int */
#define time_t int
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(HAVE_NCURSES_H)
#  include <ncurses.h>
#elif defined(HAVE_NCURSES_CURSES_H)
#  include <ncurses/curses.h>
#elif defined(HAVE_CURSES_H)
#  include <curses.h>
#elif defined(HAVE_CURSESX_H)
#  include <cursesX.h>
#else
#  error No curses header file available
#endif

#ifndef HAVE_ATTRON
#define attron(x) 
#define attroff(x) 
#endif

#ifndef getmaxyx
#  define getmaxyx(win,y,x)	((y) = (win)->_maxy + 1, (x) = (win)->_maxx + 1)
#endif

#include "mtr.h"
#include "mtr-curses.h"
#include "display.h"
#include "net.h"
#include "dns.h"
#ifndef NO_IPINFO
#include "asn.h"
#endif
#include "version.h"
#endif

#include <time.h>

extern char LocalHostname[];
extern int fstTTL;
extern int maxTTL;
extern int cpacketsize;
extern int bitpattern;
extern int tos;
extern float WaitTime;
extern int af;
extern int mtrtype;

static int __unused_int;

void pwcenter(char *str) 
{
  int maxx;
  int cx;

  getmaxyx(stdscr, __unused_int, maxx);
  cx = (signed)(maxx - strlen(str)) / 2;
  while(cx-- > 0)
    printw(" ");
  printw(str);
}


int mtr_curses_keyaction(void)
{
  int c = getch();
  int i=0;
  float f = 0.0;
  char buf[MAXFLD+1];

  if(c == 'q')
    return ActionQuit;
  if(c==3)
     return ActionQuit;
  if (c==12)
     return ActionClear;
  if ((c==19) || (tolower (c) == 'p'))
     return ActionPause;
  if ((c==17) || (c == ' '))
     return ActionResume;
  if(tolower(c) == 'r')
    return ActionReset;
  if (tolower(c) == 'd')
    return ActionDisplay;
  if (tolower(c) == 'e')
    return ActionMPLS;
  if (tolower(c) == 'n')
    return ActionDNS;
#ifndef NO_IPINFO
  if (tolower(c) == 'y')
    return ActionII;
  if (tolower(c) == 'z')
    return ActionAS;
#endif
  if (c == '+')
    return ActionScrollDown;
  if (c == '-')
    return ActionScrollUp;

  if (tolower(c) == 's') {
    mvprintw(2, 0, "Change Packet Size: %d\n", cpacketsize );
    mvprintw(3, 0, "Size Range: %d-%d, < 0:random.\n", MINPACKET, MAXPACKET);
    move(2,20);
    refresh();
    while ( (c=getch ()) != '\n' && i < MAXFLD ) {
      attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh ();
      buf[i++] = c;   /* need more checking on 'c' */
    }
    buf[i] = '\0';
    cpacketsize = atoi ( buf );
    return ActionNone;
  }
  if (tolower(c) == 'b') {
    mvprintw(2, 0, "Ping Bit Pattern: %d\n", bitpattern );
    mvprintw(3, 0, "Pattern Range: 0(0x00)-255(0xff), <0 random.\n");
    move(2,18);
    refresh();
    while ( (c=getch ()) != '\n' && i < MAXFLD ) {
      attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh ();
      buf[i++] = c;   /* need more checking on 'c' */
    }
    buf[i] = '\0';
    bitpattern = atoi ( buf );
    if( bitpattern > 255 ) { bitpattern = -1; }
    return ActionNone;
  }
  if ( c == 'Q') {    /* can not be tolower(c) */
    mvprintw(2, 0, "Type of Service(tos): %d\n", tos );
    mvprintw(3, 0, "default 0x00, min cost 0x02, rel 0x04,, thr 0x08, low del 0x10...\n");
    move(2,22);
    refresh();
    while ( (c=getch ()) != '\n' && i < MAXFLD ) {
      attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh();
      buf[i++] = c;   /* need more checking on 'c' */
    }
    buf[i] = '\0';
    tos = atoi ( buf );
    if( tos > 255 || tos <0 ) {
      tos = 0;
    }
    return ActionNone;
  }
  if (tolower(c) == 'i') {
    mvprintw(2, 0, "Interval : %0.0f\n\n", WaitTime );
    move(2,11);
    refresh();
    while ( (c=getch ()) != '\n' && i < MAXFLD ) {
      attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh();
      buf[i++] = c;   /* need more checking on 'c' */
    }
    buf[i] = '\0';

    f = atof( buf );

    if (f <= 0.0) return ActionNone;
    if (getuid() != 0 && f < 1.0)
      return ActionNone;
    WaitTime = f;

    return ActionNone;
  }
  if (tolower(c) == 'f') {
    mvprintw(2, 0, "First TTL: %d\n\n", fstTTL );
    move(2,11);
    refresh();
    while ( (c=getch ()) != '\n' && i < MAXFLD ) {
      attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh();
      buf[i++] = c;   /* need more checking on 'c' */
    }
    buf[i] = '\0';
    i = atoi( buf );

    if ( i < 1 || i> maxTTL ) return ActionNone;
    fstTTL = i;

    return ActionNone;
  }
  if (tolower(c) == 'm') {
    mvprintw(2, 0, "Max TTL: %d\n\n", maxTTL );
    move(2,9);
    refresh();
    while ( (c=getch ()) != '\n' && i < MAXFLD ) {
      attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh();
      buf[i++] = c;   /* need more checking on 'c' */
    }
    buf[i] = '\0';
    i = atoi( buf );

    if ( i < fstTTL || i>(MaxHost-1) ) return ActionNone;
    maxTTL = i;

    return ActionNone;
  }
  /* fields to display & their ordering */
  if (tolower(c) == 'o') {
    mvprintw(2, 0, "Fields: %s\n\n", fld_active );

    for( i=0; i<MAXFLD; i++ ){
      if( data_fields[i].descr != NULL )
          printw( "  %s\n", data_fields[i].descr);
    }
    printw("\n");
    move(2,8);                /* length of "Fields: " */
    refresh();

    i = 0;
    while ( (c=getch ()) != '\n' && i < MAXFLD ) {
      if( strchr(available_options, c) ) {
        attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh();
        buf[i++] = c; /* Only permit values in "available_options" be entered */
      } else {
        printf("\a"); /* Illegal character. Beep, ring the bell. */
      }
    }
    buf[i] = '\0';
    if ( strlen( buf ) > 0 ) strcpy( fld_active, buf );

    return ActionNone;
  }
  if (tolower(c) == 'j') {
    if( index(fld_active, 'N') ) {
      strcpy(fld_active, "DR AGJMXI");        /* GeoMean and jitter */
    } else {
      strcpy(fld_active, "LS NABWV");         /* default */
    }
    return ActionNone;
  }
  if (tolower(c) == 'u') {
    switch ( mtrtype ) {
    case IPPROTO_ICMP:
    case IPPROTO_TCP:
      mtrtype = IPPROTO_UDP;
      break;
    case IPPROTO_UDP:
      mtrtype = IPPROTO_ICMP;
      break;
    }
    return ActionNone;
  }
  if (tolower(c) == 't') {
    switch ( mtrtype ) {
    case IPPROTO_ICMP:
    case IPPROTO_UDP:
      mtrtype = IPPROTO_TCP;
      break;
    case IPPROTO_TCP:
      mtrtype = IPPROTO_ICMP;
      break;
    }
    return ActionNone;
  }
  /* reserve to display help message -Min */
  if (tolower(c) == '?'|| tolower(c) == 'h') {
    int pressanykey_row = 20;
    mvprintw(2, 0, "Command:\n" );
    printw("  ?|h     help\n" );
    printw("  p       pause (SPACE to resume)\n" );
    printw("  d       switching display mode\n" );
    printw("  e       toggle MPLS information on/off\n" );
    printw("  n       toggle DNS on/off\n" );
    printw("  r       reset all counters\n" );
    printw("  o str   set the columns to display, default str='LRS N BAWV'\n" );
    printw("  j       toggle latency(LS NABWV)/jitter(DR AGJMXI) stats\n" );
    printw("  c <n>   report cycle n, default n=infinite\n" );
    printw("  i <n>   set the ping interval to n seconds, default n=1\n" );
    printw("  f <n>   set the initial time-to-live(ttl), default n=1\n" );
    printw("  m <n>   set the max time-to-live, default n= # of hops\n" );
    printw("  s <n>   set the packet size to n or random(n<0)\n" );
    printw("  b <c>   set ping bit pattern to c(0..255) or random(c<0)\n" );
    printw("  Q <t>   set ping packet's TOS to t\n" );
    printw("  u       switch between ICMP ECHO and UDP datagrams\n" );
#ifndef NO_IPINFO
    printw("  y       switching IP info\n");
    printw("  z       toggle ASN info on/off\n");
    pressanykey_row += 2;
#endif
    printw("\n");
    mvprintw(pressanykey_row, 0, " press any key to go back..." );

    getch();                  /* get any key */
    return ActionNone;
  }

  return ActionNone;          /* ignore unknown input */
}


void mtr_curses_hosts(int startstat) 
{
  int max;
  int at;
  struct mplslen *mpls, *mplss;
  ip_t *addr, *addrs;
  int y;
  char *name;

  int i, j, k;
  int hd_len;
  char buf[1024];

  max = net_max();

  for(at = net_min () + display_offset; at < max; at++) {
    printw("%2d. ", at + 1);
    addr = net_addr(at);
    mpls = net_mpls(at);

    if( addrcmp( (void *) addr, (void *) &unspec_addr, af ) != 0 ) {
      name = dns_lookup(addr);
      if (! net_up(at))
	attron(A_BOLD);
#ifndef NO_IPINFO
      if (is_printii())
        printw(fmt_ipinfo(addr));
#endif
      if(name != NULL) {
        if (show_ips) printw("%s (%s)", name, strlongip(addr));
        else printw("%s", name);
      } else {
	printw("%s", strlongip( addr ) );
      }
      attroff(A_BOLD);

      getyx(stdscr, y, __unused_int);
      move(y, startstat);

      /* net_xxx returns times in usecs. Just display millisecs */
      hd_len = 0;
      for( i=0; i<MAXFLD; i++ ) {
	/* Ignore options that don't exist */
	/* On the other hand, we now check the input side. Shouldn't happen, 
	   can't be careful enough. */
	j = fld_index[fld_active[i]];
	if (j == -1) continue; 

	/* temporay hack for stats usec to ms... */
	if( index( data_fields[j].format, 'f' ) ) {
	  sprintf(buf + hd_len, data_fields[j].format,
		data_fields[j].net_xxx(at) /1000.0 );
	} else {
	  sprintf(buf + hd_len, data_fields[j].format,
		data_fields[j].net_xxx(at) );
	}
	hd_len +=  data_fields[j].length;
      }
      buf[hd_len] = 0;
      printw("%s", buf);

      for (k=0; k < mpls->labels && enablempls; k++) {
        if((k+1 < mpls->labels) || (mpls->labels == 1)) {
           /* if we have more labels */
           printw("\n    [MPLS: Lbl %lu Exp %u S %u TTL %u]", mpls->label[k], mpls->exp[k], mpls->s[k], mpls->ttl[k]);
        } else {
           /* bottom label */
           printw("\n    [MPLS: Lbl %lu Exp %u S %u TTL %u]", mpls->label[k], mpls->exp[k], mpls->s[k], mpls->ttl[k]);
        }
      }

      /* Multi path */
      for (i=0; i < MAXPATH; i++ ) {
        addrs = net_addrs(at, i);
        mplss = net_mplss(at, i);
	if ( addrcmp( (void *) addrs, (void *) addr, af ) == 0 ) continue;
	if ( addrcmp( (void *) addrs, (void *) &unspec_addr, af ) == 0 ) break;

        name = dns_lookup(addrs);
        if (! net_up(at)) attron(A_BOLD);
        printw("\n    ");
#ifndef NO_IPINFO
        if (is_printii())
          printw(fmt_ipinfo(addrs));
#endif
        if (name != NULL) {
	  if (show_ips) printw("%s (%s)", name, strlongip(addrs));
	  else printw("%s", name);
        } else {
	  printw("%s", strlongip( addrs ) );
        }
        for (k=0; k < mplss->labels && enablempls; k++) {
          printw("\n    [MPLS: Lbl %lu Exp %u S %u TTL %u]", mplss->label[k], mplss->exp[k], mplss->s[k], mplss->ttl[k]);
        }
        attroff(A_BOLD);
      }

    } else {
      printw("???");
    }

    printw("\n");
  }
  move(2, 0);
}

#define NUM_FACTORS 8
static double factors[NUM_FACTORS];
static int scale[NUM_FACTORS];
static int low_ms, high_ms;

void mtr_gen_scale(void) 
{
	int *saved, i, max, at;
	int range;

	low_ms = 1000000;
	high_ms = -1;

	for (i = 0; i < NUM_FACTORS; i++) {
		scale[i] = 0;
	}
	max = net_max();
	for (at = display_offset; at < max; at++) {
		saved = net_saved_pings(at);
		for (i = 0; i < SAVED_PINGS; i++) {
			if (saved[i] < 0) continue;
			if (saved[i] < low_ms) {
				low_ms = saved[i];
			}
			if (saved[i] > high_ms) {
				high_ms = saved[i];
			}
		}
	}
	range = high_ms - low_ms;
	for (i = 0; i < NUM_FACTORS; i++) {
		scale[i] = low_ms + ((double)range * factors[i]);
	}
}


static char block_map[NUM_FACTORS];

void mtr_curses_init() {
	int i;
	int block_split;

	/* Initialize factors to a log scale. */
	for (i = 0; i < NUM_FACTORS; i++) {
		factors[i] = ((double)1 / NUM_FACTORS) * (i + 1);
		factors[i] *= factors[i]; /* Squared. */
	}

	/* Initialize block_map. */
	block_split = (NUM_FACTORS - 2) / 2;
	if (block_split > 9) {
		block_split = 9;
	}
	for (i = 1; i <= block_split; i++) {
		block_map[i] = '0' + i;
	}
	for (i = block_split+1; i < NUM_FACTORS-1; i++) {
		block_map[i] = 'a' + i - block_split - 1;
	}
	block_map[0] = '.';
	block_map[NUM_FACTORS-1] = '>';
}


void mtr_print_scaled(int ms) 
{
	int i;

	for (i = 0; i < NUM_FACTORS; i++) {
		if (ms <= scale[i]) {
			printw("%c", block_map[i]);
			return;
		}
	}
	printw(">");
}


void mtr_fill_graph(int at, int cols) 
{
	int* saved;
	int i;

	saved = net_saved_pings(at);
	for (i = SAVED_PINGS-cols; i < SAVED_PINGS; i++) {
		if (saved[i] == -2) {
			printw(" ");
		} else if (saved[i] == -1) {
			attron(A_BOLD);
			printw("?");
			attroff(A_BOLD);
		} else {
			if (display_mode == 1) {
				if (saved[i] > scale[6]) {
					printw("%c", block_map[NUM_FACTORS-1]);
				} else {
					printw(".");
				}
			} else {
				mtr_print_scaled(saved[i]);
			}
		}
	}
}


void mtr_curses_graph(int startstat, int cols) 
{
	int max, at, y;
	ip_t * addr;
	char* name;

	max = net_max();

	for (at = display_offset; at < max; at++) {
		printw("%2d. ", at+1);

		addr = net_addr(at);
		if (!addr) {
			printw("???\n");
			continue;
		}

		if (! net_up(at))
			attron(A_BOLD);
		if (addrcmp((void *) addr, (void *) &unspec_addr, af)) {
#ifndef NO_IPINFO
			if (is_printii())
				printw(fmt_ipinfo(addr));
#endif
			name = dns_lookup(addr);
			printw("%s", name?name:strlongip(addr));
		} else
			printw("???");
		attroff(A_BOLD);

		getyx(stdscr, y, __unused_int);
		move(y, startstat);

		printw(" ");
		mtr_fill_graph(at, cols);
		printw("\n");
	}
}


void mtr_curses_redraw(void)
{
  int maxx;
  int startstat;
  int rowstat;
  time_t t;

  int i, j;
  int  hd_len = 0;
  char buf[1024];
  char fmt[16];
  

  erase();
  getmaxyx(stdscr, __unused_int, maxx);

  rowstat = 5;

  move(0, 0);
  attron(A_BOLD);
  pwcenter("My traceroute  [v" MTR_VERSION "]");
  attroff(A_BOLD);

  mvprintw(1, 0, "%s (%s)", LocalHostname, net_localaddr());
  /*
  printw("(tos=0x%X ", tos);
  printw("psize=%d ", packetsize );
  printw("bitpattern=0x%02X)", (unsigned char)(abs(bitpattern)));
  if( cpacketsize > 0 ){
    printw("psize=%d ", cpacketsize);
  } else {
    printw("psize=rand(%d,%d) ",MINPACKET, -cpacketsize);
  }
  if( bitpattern>=0 ){
    printw("bitpattern=0x%02X)", (unsigned char)(bitpattern));
  } else {
    printw("bitpattern=rand(0x00-FF))");
  }
  */
  time(&t);
  mvprintw(1, maxx-25, ctime(&t));

  printw("Keys:  ");
  attron(A_BOLD); printw("H"); attroff(A_BOLD); printw("elp   ");
  attron(A_BOLD); printw("D"); attroff(A_BOLD); printw("isplay mode   ");
  attron(A_BOLD); printw("R"); attroff(A_BOLD); printw("estart statistics   ");
  attron(A_BOLD); printw("O"); attroff(A_BOLD); printw("rder of fields   ");
  attron(A_BOLD); printw("q"); attroff(A_BOLD); printw("uit\n");
  
  if (display_mode == 0) {
    for (i=0; i < MAXFLD; i++ ) {
	j = fld_index[fld_active[i]];
	if (j < 0) continue;

	sprintf( fmt, "%%%ds", data_fields[j].length );
        sprintf( buf + hd_len, fmt, data_fields[j].title );
	hd_len +=  data_fields[j].length;
    }
    attron(A_BOLD);
    mvprintw(rowstat - 1, 0, " Host");
    mvprintw(rowstat - 1, maxx-hd_len-1, "%s", buf);
    mvprintw(rowstat - 2, maxx-hd_len-1, "   Packets               Pings");
    attroff(A_BOLD);

    move(rowstat, 0);
    mtr_curses_hosts(maxx-hd_len-1);

  } else {
    char msg[80];
    int padding = 30;
#ifndef NO_IPINFO
    if (is_printii())
      padding += get_iiwidth();
#endif
    int max_cols = maxx<=SAVED_PINGS+padding ? maxx-padding : SAVED_PINGS;
    startstat = padding - 2;

    sprintf(msg, " Last %3d pings", max_cols);
    mvprintw(rowstat - 1, startstat, msg);
    
    attroff(A_BOLD);
    move(rowstat, 0);

    mtr_gen_scale();
    mtr_curses_graph(startstat, max_cols);

    printw("\n");
    attron(A_BOLD);
    printw("Scale:");
    attroff(A_BOLD);
    
    for (i = 0; i < NUM_FACTORS-1; i++) {
      printw("  %c:%d ms", block_map[i], scale[i]/1000);
    }
  }

  refresh();
}


void mtr_curses_open(void)
{
  initscr();
  raw();
  noecho(); 

  mtr_curses_init();
  mtr_curses_redraw();
}


void mtr_curses_close(void)
{  
  printw("\n");
  endwin();
}


void mtr_curses_clear(void)
{
  mtr_curses_close();
  mtr_curses_open();
}
