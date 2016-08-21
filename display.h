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

#include <netinet/in.h>

/* Don't put a trailing comma in enumeration lists. Some compilers 
   (notably the one on Irix 5.2) do not like that. */ 
enum { ActionNone,  ActionQuit,  ActionReset,  ActionDisplay, 
       ActionClear, ActionPause, ActionResume, ActionMPLS, ActionDNS, 
#ifdef HAVE_IPINFO
       ActionII, ActionAS,
#endif
       ActionScrollDown, ActionScrollUp  };

enum {
  DisplayReport,
#ifdef HAVE_NCURSES
  DisplayCurses,
#endif
#ifdef HAVE_GTK
  DisplayGTK,
#endif
  DisplaySplit,
  DisplayRaw,
  DisplayXML,
  DisplayCSV,
  DisplayTXT,
  DisplayJSON
};

/*  Prototypes for display.c  */
void display_detect(int *argc, char ***argv);
void display_open(void);
void display_close(time_t now);
void display_redraw(void);
void display_rawxmit(int hostnum, int seq);
void display_rawping(int hostnum, int msec, int seq);
void display_rawhost(int hostnum, ip_t *ip_addr);
int display_keyaction(void);
void display_loop(void);
void display_clear(void);

extern int display_mode;
extern int display_offset; /* only used in text mode */
