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

#ifndef NO_CURSES
  case DisplayCurses:
    mtr_curses_open();  
    break;
#endif

#ifndef NO_GTK
  case DisplayGTK:
    gtk_open();
    break;
#endif
  }
}

void display_close() {
  switch(DisplayMode) {
  case DisplayReport:
    report_close();
    break;

#ifndef NO_CURSES
  case DisplayCurses:
    mtr_curses_close();
    break;
#endif

#ifndef NO_GTK
  case DisplayGTK:
    gtk_close();
    break;
#endif
  }
}

void display_redraw() {
  switch(DisplayMode) {
#ifndef NO_CURSES
  case DisplayCurses:
    mtr_curses_redraw();
    break;
#endif

#ifndef NO_GTK
  case DisplayGTK:
    gtk_redraw();
    break;
#endif
  }
}

int display_keyaction() {
  switch(DisplayMode) {
#ifndef NO_CURSES
  case DisplayCurses:
    return mtr_curses_keyaction();
#endif

#ifndef NO_GTK
  case DisplayGTK:
    return gtk_keyaction();
#endif
  }
  return 0;
}

void display_loop() {
  switch(DisplayMode) {
  case DisplayCurses:
  case DisplayReport:
    select_loop();
    break;

#ifndef NO_GTK
  case DisplayGTK:
    gtk_loop();
    break;
#endif
  }
}

