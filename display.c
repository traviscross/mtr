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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "mtr.h"
#include "display.h"
#include "mtr-curses.h"
#include "mtr-gtk.h"
#include "report.h"
#include "select.h"
#include "raw.h"
#include "dns.h"
#include "asn.h"

extern int DisplayMode;

#ifdef HAVE_NCURSES
#include "mtr-curses.h"
#endif

#ifdef HAVE_GTK
#include "mtr-gtk.h"
#endif

#include "split.h"

#ifdef HAVE_NCURSES
#define DEFAULT_DISPLAY DisplayCurses
#else
#define DEFAULT_DISPLAY DisplayReport
#endif

#ifdef HAVE_GTK
#define UNUSED_IF_NO_GTK
#else
#define UNUSED_IF_NO_GTK UNUSED
#endif

void display_detect(int *argc UNUSED_IF_NO_GTK, char ***argv UNUSED_IF_NO_GTK)
{
  DisplayMode = DEFAULT_DISPLAY;

#ifdef HAVE_GTK
  if(gtk_detect(argc, argv)) {
    DisplayMode = DisplayGTK;
  }
#endif
}


void display_open(void)
{
  switch(DisplayMode) {

  case DisplayReport:
    report_open();
    break;
  case DisplayTXT:
    txt_open();
    break;
  case DisplayJSON:
    json_open();
    break;
  case DisplayXML:
    xml_open();
    break;
  case DisplayCSV:
    csv_open();
    break;
#ifdef HAVE_NCURSES
  case DisplayCurses:
    mtr_curses_open();  
#ifdef HAVE_IPINFO
    asn_open();
#endif
    break;
#endif
  case DisplaySplit:
    split_open();
    break;
#ifdef HAVE_GTK
  case DisplayGTK:
    gtk_open();
#ifdef HAVE_IPINFO
    asn_open();
#endif
    break;
#endif
  }
}


void display_close(time_t now)
{
  switch(DisplayMode) {
  case DisplayReport:
    report_close();
    break;
  case DisplayTXT:
    txt_close();
    break;
  case DisplayJSON:
    json_close();
    break;
  case DisplayXML:
    xml_close();
    break;
  case DisplayCSV:
    csv_close(now);
    break;
#ifdef HAVE_NCURSES
  case DisplayCurses:
#ifdef HAVE_IPINFO
    asn_close();
#endif
    mtr_curses_close();
    break;
#endif
  case DisplaySplit:
    split_close();
    break;
#ifdef HAVE_GTK
  case DisplayGTK:
    gtk_close();
    break;
#endif
  }
}


void display_redraw(void)
{
  switch(DisplayMode) {

#ifdef HAVE_NCURSES
  case DisplayCurses:
    mtr_curses_redraw();
    break;
#endif

  case DisplaySplit:
    split_redraw();
    break;

#ifdef HAVE_GTK
  case DisplayGTK:
    gtk_redraw();
    break;
#endif
  }
}


int display_keyaction(void)
{
  switch(DisplayMode) {
#ifdef HAVE_NCURSES
  case DisplayCurses:
    return mtr_curses_keyaction();
#endif

  case DisplaySplit:
    return split_keyaction();

#ifdef HAVE_GTK
  case DisplayGTK:
    return gtk_keyaction();
#endif
  }
  return 0;
}


void display_rawxmit(int host, int seq)
{
  switch(DisplayMode) {
  case DisplayRaw:
    raw_rawxmit (host, seq);
    break;
  }
}


void display_rawping(int host, int msec, int seq)
{
  switch(DisplayMode) {
  case DisplayReport:
  case DisplayTXT:
  case DisplayJSON:
  case DisplayXML:
  case DisplayCSV:
  case DisplaySplit:
#ifdef HAVE_NCURSES
  case DisplayCurses:
#endif
#ifdef HAVE_GTK
  case DisplayGTK:
#endif
    break;
  case DisplayRaw:
    raw_rawping (host, msec, seq);
    break;
  }
}


void display_rawhost(int host, ip_t *ip_addr) 
{
  switch(DisplayMode) {
  case DisplayReport:
  case DisplayTXT:
  case DisplayJSON:
  case DisplayXML:
  case DisplayCSV:
  case DisplaySplit:
#ifdef HAVE_NCURSES
  case DisplayCurses:
#endif
#ifdef HAVE_GTK
  case DisplayGTK:
#endif
    break;
  case DisplayRaw:
    raw_rawhost (host, ip_addr);
    break;
  }
}


void display_loop(void)
{
  switch(DisplayMode) {
  case DisplayReport:
  case DisplayTXT:
  case DisplayJSON:
  case DisplayXML:
  case DisplayCSV:
  case DisplaySplit:
#ifdef HAVE_NCURSES
  case DisplayCurses:
#endif
  case DisplayRaw:
    select_loop();
    break;
#ifdef HAVE_GTK
  case DisplayGTK:
    gtk_loop();
    break;
#endif
  }
}


void display_clear(void)
{
  switch(DisplayMode) {
#ifdef HAVE_NCURSES
  case DisplayCurses:
    mtr_curses_clear();
    break;
#endif
  case DisplayReport:
  case DisplayTXT:
  case DisplayJSON:
  case DisplayXML:
  case DisplayCSV:
  case DisplaySplit:
  case DisplayRaw:
    break;

#ifdef HAVE_GTK
  case DisplayGTK:
    break;
#endif
  }
}
