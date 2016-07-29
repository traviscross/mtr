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

#ifdef NO_CURSES
#define mtr_curses_open()
#define mtr_curses_close()
#define mtr_curses_redraw()
#define mtr_curses_keyaction() 0
#define mtr_curses_clear()
#else
#include "mtr-curses.h"
#endif

#ifdef NO_GTK
#define gtk_open()
#define gtk_close()
#define gtk_redraw()
#define gtk_keyaction() 0
#define gtk_loop() {fprintf (stderr, "No GTK support. Sorry.\n"); exit (1); } 
#else
#include "mtr-gtk.h"
#endif

#ifdef NO_SPLIT
#define split_open()
#define split_close()
#define split_redraw()
#define split_keyaction() 0
#else
#include "split.h"
#endif

void display_detect(int *argc, char ***argv) {
  DisplayMode = DisplayReport;

#ifndef NO_CURSES
  DisplayMode = DisplayCurses;
#endif

#ifndef NO_GTK
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
  case DisplayCurses:
    mtr_curses_open();  
#ifdef IPINFO
    if (ipinfo_no >= 0)
        asn_open();
#endif
    break;
  case DisplaySplit:
    split_open();
    break;
  case DisplayGTK:
    gtk_open();
#ifdef IPINFO
    if (ipinfo_no >= 0)
        asn_open();
#endif
    break;
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
  case DisplayCurses:
#ifdef IPINFO
    if (ipinfo_no >= 0)
        asn_close();
#endif
    mtr_curses_close();
    break;
  case DisplaySplit:
    split_close();
    break;
  case DisplayGTK:
    gtk_close();
    break;
  }
}


void display_redraw(void)
{
  switch(DisplayMode) {

  case DisplayCurses:
    mtr_curses_redraw();
    break;

  case DisplaySplit:
    split_redraw();
    break;

  case DisplayGTK:
    gtk_redraw();
    break;
  }
}


int display_keyaction(void)
{
  switch(DisplayMode) {
  case DisplayCurses:
    return mtr_curses_keyaction();

  case DisplaySplit:
    return split_keyaction();

  case DisplayGTK:
    return gtk_keyaction();
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
  case DisplayCurses:
  case DisplayGTK:
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
  case DisplayCurses:
  case DisplayGTK:
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
  case DisplayCurses:
  case DisplayRaw:
    select_loop();
    break;
  case DisplayGTK:
    gtk_loop();
    break;
  }
}


void display_clear(void)
{
  switch(DisplayMode) {
  case DisplayCurses:
    mtr_curses_clear();
    break;
  case DisplayReport:
  case DisplayTXT:
  case DisplayJSON:
  case DisplayXML:
  case DisplayCSV:
  case DisplaySplit:
  case DisplayRaw:
    break;

  case DisplayGTK:
    break;
  }
}
