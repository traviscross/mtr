/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997  Matt Kimball

    split.c -- raw output (for inclusion in KDE Network Utilities or others
                         GUI based tools)
    Copyright (C) 1998  Bertrand Leconte <B.Leconte@mail.dotcom.fr>

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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "display.h"
#include "dns.h"

#include "net.h"
#include "split.h"


#include <config.h>

#ifdef NO_CURSES
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#else
/* Use the curses variant */

#if defined(HAVE_NCURSES_H)
#  include <ncurses.h>
#elif defined(HAVE_NCURSES_CURSES_H)
#  include <ncurses/curses.h>
#elif defined(HAVE_CURSES_H)
#  include <curses.h>
#else
#  error No curses header file available
#endif

#endif


extern char *Hostname;
extern int WaitTime;

/* There is 256 hops max in the IP header (coded with a byte) */
#define MAX_LINE_COUNT 256
#define MAX_LINE_SIZE  256

char Lines[MAX_LINE_COUNT][MAX_LINE_SIZE];
int  LineCount;


#define DEBUG 0

void 
split_redraw() {
  int   max;
  int   at;
  int   addr;
  char *name;
  char  newLine[MAX_LINE_SIZE];
  int   i;

#if DEBUG
  fprintf(stderr, "split_redraw()\n"); 
#endif

  /* 
   * If there is less lines than last time, we delete them
   * TEST THIS PLEASE
   */
  max = net_max();
  for (i=LineCount; i>max; i--) {
    printf("-%d\n", i);
    LineCount--;
  }

  /*
   * For each line, we compute the new one and we compare it to the old one
   */
  for(at = 0; at < max; at++) {
    addr = net_addr(at);
    
    if(addr != 0) {
      name = dns_lookup(addr);
      if(name != NULL) {
	/* May be we should test name's length */
	sprintf(newLine, "%s %d %d %d %d %d %d", name,
		net_loss(at),
		net_returned(at), net_xmit(at),
		net_best(at) /1000, net_avg(at)/1000, 
		net_worst(at)/1000);
      } else {
	sprintf(newLine, "%d.%d.%d.%d %d %d %d %d %d %d", 
		(addr >> 24) & 0xff, (addr >> 16) & 0xff, 
		(addr >> 8) & 0xff, addr & 0xff,
		net_loss(at),
		net_returned(at), net_xmit(at),
		net_best(at) /1000, net_avg(at)/1000, 
		net_worst(at)/1000);
      }
    } else {
      sprintf(newLine, "???");
    }

    if (strcmp(newLine, Lines[at]) == 0) {
      /* The same, so do nothing */
#if DEBUG
      printf("SAME LINE\n");
#endif
    } else {
      printf("%d %s\n", at+1, newLine);
      fflush(stdout);
      strcpy(Lines[at], newLine);
      if (LineCount < (at+1)) {
	LineCount = at+1;
      }
    }
  }
}

void 
split_open() {
  int i;
#if DEBUG
  printf("split_open()\n");
#endif
  LineCount = -1;
  for (i=0; i<MAX_LINE_COUNT; i++) {
    strcpy(Lines[i], "???");
  }
}

void 
split_close() {
#if DEBUG
  printf("split_close()\n");
#endif
}

int 
split_keyaction() {
#ifdef NO_CURSES
  fd_set readfds;
  struct timeval tv;
  char c;

  FD_ZERO (&readfds);
  FD_SET (0, &readfds);
  tv.tv_sec = 0;
  tv.tv_usec = 0;

  if (select (1, &readfds, NULL, NULL, &tv) > 0) {
    read (0, &c, 1);
  } else 
    return 0;
#else
  char c = getch();
#endif

#if DEBUG
  printf("split_keyaction()\n");
#endif
  if(tolower(c) == 'q')
    return ActionQuit;
  if(c==3)
    return ActionQuit;
  if(tolower(c) == 'r')
    return ActionReset;
  
  return 0;
}
