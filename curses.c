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

#include <config.h>

#ifndef NO_CURSES
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

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

#if defined(HAVE_SYS_TYPES_H)
#include <sys/types.h>
#else
/* If a system doesn't have sys/types.h, lets hope that time_t is an int */
#define time_t int
#endif

#ifndef HAVE_ATTRON
#define attron(x) 
#define attroff(x) 
#endif

#ifndef getmaxyx
#  define getmaxyx(win,y,x)	((y) = (win)->_maxy + 1, (x) = (win)->_maxx + 1)
#endif

#include "mtr-curses.h"
#include "display.h"
#include "net.h"
#include "dns.h"
#endif

#include <time.h>

extern char LocalHostname[];
extern int fstTTL;
extern int maxTTL;
extern int packetsize;
extern int bitpattern;
extern int tos;
extern float WaitTime;


void pwcenter(char *str) 
{
  int maxx, maxy;
  int cx;

  getmaxyx(stdscr, maxy, maxx);
  cx = (signed)(maxx - strlen(str)) / 2;
  while(cx-- > 0)
    printw(" ");
  printw(str);
}

int mtr_curses_keyaction() 
{
  int c = getch();
  int i=0;
  char buf[MAXFLD];

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
  if (tolower(c) == 'n')
    return ActionDNS;
  if (c == '+')
    return ActionScrollDown;
  if (c == '-')
    return ActionScrollUp;

  /* more stuffs added by Min */
  if (tolower(c) == 's') {
    mvprintw(2, 0, "Change Packet Size: %d\n", packetsize );
    mvprintw(3, 0, "Size Range: %d-%d, <0 random.\n", MINPACKET, MAXPACKET);
    move(2,20);
    refresh();
    while ( (c=getch ()) != '\n' && i<MAXFLD ) {
      attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh ();
      buf[i++] = c;   /* need more checking on 'c' */
    }
    buf[i] = '\0';
    packetsize = atoi ( buf );
    if( packetsize >=0 ) {
      if ( packetsize < MINPACKET ) packetsize = MINPACKET;
      if ( packetsize > MAXPACKET ) packetsize = MAXPACKET;
    } else {
      packetsize =
      - (int)(MINPACKET + (MAXPACKET-MINPACKET)*(rand()/(RAND_MAX+0.1)));
    }

    return ActionNone;
  }
  if (tolower(c) == 'b') {
    mvprintw(2, 0, "Ping Bit Pattern: %d\n", bitpattern );
    mvprintw(3, 0, "Pattern Range: 0(0x00)-255(0xff), <0 random.\n");
    move(2,18);
    refresh();
    while ( (c=getch ()) != '\n' && i<MAXFLD ) {
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
    while ( (c=getch ()) != '\n' && i<MAXFLD ) {
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
    while ( (c=getch ()) != '\n' && i<MAXFLD ) {
      attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh();
      buf[i++] = c;   /* need more checking on 'c' */
    }
    buf[i] = '\0';
    i = atoi( buf );

    if ( i < 1 ) return ActionNone;
    WaitTime = (float) i;

    return ActionNone;
  }
  if (tolower(c) == 'f') {
    mvprintw(2, 0, "First TTL: %d\n\n", fstTTL );
    move(2,11);
    refresh();
    while ( (c=getch ()) != '\n' && i<MAXFLD ) {
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
    while ( (c=getch ()) != '\n' && i<MAXFLD ) {
      attron(A_BOLD); printw("%c", c); attroff(A_BOLD); refresh();
      buf[i++] = c;   /* need more checking on 'c' */
    }
    buf[i] = '\0';
    i = atoi( buf );

    if ( i < fstTTL || i>(MaxHost-1) ) return ActionNone;
    maxTTL = i;

    return ActionNone;
  }
  /* fields to display & their ordering -Min */
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
  /* reserve to display help message -Min */
  if (tolower(c) == '?'|| tolower(c) == 'h') {
    mvprintw(2, 0, "Command:\n" );
    printw("  ?|h     help\n" );
    printw("  d       switching display mode\n" );
    printw("  n       toggle DNS on/off\n" );
    printw("  o str   set the columns to display, default str='LRS N BAWV'\n" );
    printw("  j       toggle latency(LS NABWV)/jitter(DR AGJMXI) stats\n" );
    printw("  c <n>   report cycle n, default n=infinite\n" );
    printw("  i <n>   set the ping interval to n seconds, default n=1\n" );
    printw("  f <n>   set the initial time-to-live(ttl), default n=1\n" );
    printw("  m <n>   set the max time-to-live, default n= # of hops\n" );
    printw("  s <n>   set the packet size to n or random(n<0)\n" );
    printw("  b <c>   set ping bit pattern to c(0..255) or random(c<0)\n" );
    printw("  Q <t>   set ping packet's TOS to t\n\n\n" );
    mvprintw(16, 0, " press any key to go back..." );

    getch();                  /* get any key */
    return ActionNone;
  }

  return ActionNone;          /* ignore unknown input */
}

void mtr_curses_hosts(int startstat) 
{
  int max;
  int at;
  int addr, addrs;
  int y, x;
  char *name;

  int i, j;
  int hd_len;
  char buf[1024];

  max = net_max();

  for(at = net_min () + display_offset; at < max; at++) {
    printw("%2d. ", at + 1);
    addr = net_addr(at);

    if(addr != 0) {
      name = dns_lookup(addr);
      if (! net_up(at))
	attron(A_BOLD);
      if(name != NULL) {
	printw("%s", name);
      } else {
	printw("%d.%d.%d.%d", (addr >> 24) & 0xff, (addr >> 16) & 0xff, 
	       (addr >> 8) & 0xff, addr & 0xff);
      }
      attroff(A_BOLD);

      getyx(stdscr, y, x);
      move(y, startstat);

      /* net_xxx returns times in usecs. Just display millisecs */
      /* changedByMin */
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

      /* Multi path by Min */
      for (i=0; i < MAXPATH; i++ ) {
        addrs = net_addrs(at, i);
	if (addrs == addr) continue;
	if (addrs == 0) break;

        name = dns_lookup(addrs);
        if (! net_up(at)) attron(A_BOLD);
        if (name != NULL) {
	  printw("\n    %s", name);
        } else {
	  printw("\n    %d.%d.%d.%d",
		(addrs >> 24) & 0xff, (addrs >> 16) & 0xff, 
		(addrs >> 8) & 0xff, addrs & 0xff);
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

static double factors[] = { 0.02, 0.05, 0.08, 0.15, 0.33, 0.50, 0.80, 1.00 };
static int scale[8];
static int low_ms, high_ms;

void mtr_gen_scale(void) 
{
	int *saved, i, max, at;
	int range;

	low_ms = 1000000;
	high_ms = -1;

	for (i = 0; i < 8; i++) {
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
	for (i = 0; i < 8; i++) {
		scale[i] = low_ms + ((double)range * factors[i]);
	}
}

static const char* block_map = ".123abc>";

void mtr_print_scaled(int ms) 
{
	int i;

	for (i = 0; i < 8; i++) {
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
					printw("%c", block_map[7]);
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
	int max, at, addr, y, x;
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
		name = dns_lookup(addr);
		if (name) {
			printw("%s", name);
		} else {
			printw("%d.%d.%d.%d", (addr >> 24) & 0xff, (addr >> 16) && 0xff, (addr >> 8) & 0xff, addr & 0xff);
		}
		attroff(A_BOLD);

		getyx(stdscr, y, x);
		move(y, startstat);

		printw(" ");
		mtr_fill_graph(at, cols);
		printw("\n");
	}
}

void mtr_curses_redraw() 
{
  int maxx, maxy;
  int startstat;
  int rowstat;
  time_t t;

  int i, j;
  int  hd_len = 0;
  char buf[1024];
  char fmt[16];

  erase();
  getmaxyx(stdscr, maxy, maxx);

  rowstat = 5;

  move(0, 0);
  attron(A_BOLD);
  pwcenter("My traceroute  [v" VERSION "]");
  attroff(A_BOLD);

  mvprintw(1, 0, "%s", LocalHostname);
  printw("(tos=0x%X ", tos);
  printw("psize=%d ", abs(packetsize) );
  printw("bitpattern=0x%02X)", (unsigned char)(abs(bitpattern)));
  /*
  if( packetsize>0 ){
    printw("psize=%d ", packetsize);
  } else {
    printw("psize=rand(%d,%d) ",MINPACKET, MAXPACKET);
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
    /* changedByMin */
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
    /* David Sward, Jan 1999 */
    char msg[80];
    int max_cols = maxx<=SAVED_PINGS+30 ? maxx-30 : SAVED_PINGS;
    startstat = 28;

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
    
    for (i = 0; i < 7; i++) {
      printw("  %c:%d ms", block_map[i], scale[i]/1000);
    }
  }

  refresh();
}


void mtr_curses_open() 
{
  initscr();
  raw();
  noecho(); 

  mtr_curses_redraw();
}


void mtr_curses_close() 
{  
  printw("\n");
  endwin();
}


void mtr_curses_clear() 
{
  mtr_curses_close();
  mtr_curses_open();
}
