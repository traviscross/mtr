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
#include "display.h"
#include "mtr-curses.h"
#include "mtr-gtk.h"
#include "report.h"
#include "select.h"

extern int DisplayMode;

#ifdef NO_CURSES
#define mtr_curses_open()
#define mtr_curses_close()
#define mtr_curses_redraw()
#define mtr_curses_keyaction()
#endif

#ifdef NO_GTK
#define gtk_open()
#define gtk_close()
#define gtk_redraw()
#define gtk_keyaction()
#define gtk_loop()
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

void display_open() {
  switch(DisplayMode) {
  case DisplayReport:
    report_open();
    break;

  case DisplayCurses:
    mtr_curses_open();  
    break;

  case DisplaySplit:            /* BL */
    split_open();
    break;

  case DisplayGTK:
    gtk_open();
    break;
  }
}

void display_close() {
  switch(DisplayMode) {
  case DisplayReport:
    report_close();
    break;

  case DisplayCurses:
    mtr_curses_close();
    break;

  case DisplaySplit:            /* BL */
    split_close();
    break;
    
  case DisplayGTK:
    gtk_close();
    break;
  }
}

void display_redraw() {
  switch(DisplayMode) {

  case DisplayCurses:
    mtr_curses_redraw();
    break;

  case DisplaySplit:            /* BL */
    split_redraw();
    break;

  case DisplayGTK:
    gtk_redraw();
    break;
  }
}

int display_keyaction() {
  switch(DisplayMode) {
  case DisplayCurses:
    return mtr_curses_keyaction();

  case DisplaySplit:		/* BL */
    return split_keyaction();

  case DisplayGTK:
    return gtk_keyaction();
  }
  return 0;
}


void display_rawping(int host, int msec) {
  switch(DisplayMode) {
  case DisplayReport:
  case DisplaySplit:            /* BL */
  case DisplayCurses:
  case DisplayGTK:
    break;
  case DisplayRaw:
    raw_rawping (host, msec);
    break;
  }
}


void display_rawhost(int host, int ip_addr) {
  switch(DisplayMode) {
  case DisplayReport:
  case DisplaySplit:            /* BL */
  case DisplayCurses:
  case DisplayGTK:
    break;
  case DisplayRaw:
    raw_rawhost (host, ip_addr);
    break;
  }
}


void display_loop() {
  switch(DisplayMode) {
  case DisplayCurses:
  case DisplayReport:
  case DisplaySplit:            /* BL */
  case DisplayRaw:
    select_loop();
    break;

  case DisplayGTK:
    gtk_loop();
    break;
  }
}


void display_clear() {
  switch(DisplayMode) {
  case DisplayCurses:
    mtr_curses_clear();
    break;
  case DisplayReport:
  case DisplaySplit:            /* BL */
  case DisplayRaw:
    break;

  case DisplayGTK:
    break;
  }
}
