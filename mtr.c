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
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mtr-curses.h"
#include "getopt.h"
#include "display.h"
#include "dns.h"
#include "report.h"
#include "net.h"

int DisplayMode;
int Interactive = 1;
int PrintVersion = 0;
int PrintHelp = 0;
int MaxPing = 16;
float WaitTime = 1.0;
char *Hostname = NULL;
char LocalHostname[128];
int dns = 1;

void parse_arg(int argc, char **argv) {
  int opt;
  static struct option long_options[] = {
    { "version", 0, 0, 'v' },
    { "help", 0, 0, 'h' },
    { "report", 0, 0, 'r' },
    { "report-cycles", 1, 0, 'c' },
    { "curses", 0, 0, 't' },
    { "gtk", 0, 0, 'g' },
    { "interval", 1, 0, 'i' },
    { "no-dns", 0, 0, 'n' },
    { "split", 0, 0, 's' },     /* BL */
    { "raw", 0, 0, 'l' },
    { 0, 0, 0, 0 }
  };

  opt = 0;
  while(1) {
    opt = getopt_long(argc, argv, "hvrc:tklnsi:", long_options, NULL);
    if(opt == -1)
      break;

    switch(opt) {
    case 'v':
      PrintVersion = 1;
      break;
    case 'h':
      PrintHelp = 1;
      break;
    case 'r':
      DisplayMode = DisplayReport;
      break;
    case 'c':
      MaxPing = atoi(optarg);
      break;
    case 't':
      DisplayMode = DisplayCurses;
      break;
    case 'g':
      DisplayMode = DisplayGTK;
      break;
    case 's':                 /* BL */
      DisplayMode = DisplaySplit;
      break;
    case 'l':
      DisplayMode = DisplayRaw;
      break;
    case 'n':
      dns = 0;
      break;
    case 'i':
      WaitTime = atof(optarg);
      if (WaitTime <= 0.0) {
	fprintf (stderr, "mtr: wait time must be positive\n");
	exit (1);
      }
      if (getuid() != 0 && WaitTime < 1.0)
       WaitTime = 1.0;
      break;
    }
  }

  if(DisplayMode == DisplayReport)
    Interactive = 0;

  if(optind != argc - 1)
    return;

  Hostname = argv[optind];

}


void parse_mtr_options (char *string)
{
  int argc;
  char *argv[128], *p;
  int i;

  if (!string) return;

  argv[0] = "mtr";
  argc = 1;
  p = strtok (string, " \t");
  while (p) {
    argv[argc++] = p;
    p = strtok (NULL, " \t");
  }
  parse_arg (argc, argv);
  optind = 0;
}


int main(int argc, char **argv) {
  int traddr;
  struct hostent *host;
  int net_preopen_result;

  /*  Get the raw sockets first thing, so we can drop to user euid immediately  */

  net_preopen_result = net_preopen ();

  /*  Now drop to user permissions  */
  if(seteuid(getuid())) {
    printf("mtr: Unable to drop permissions.\n");
    exit(1);
  }

  /*  Double check, just in case  */
  if(geteuid() != getuid()) {
    printf("mtr: Unable to drop permissions.\n");
    exit(1);
  }
  
  display_detect(&argc, &argv);

  parse_mtr_options (getenv ("MTR_OPTIONS"));

  parse_arg(argc, argv);

  if(PrintVersion) {
    printf("mtr " VERSION "\n");
    exit(0);
  }

  if(PrintHelp) {
    printf("usage: %s [-hvrctglsni] [--help] [--version] [--report]\n"
	   "\t\t[--report-cycles=COUNT] [--curses] [--gtk]\n"
           "\t\t[--raw] [--split] [--no-dns]\n"      /* BL */
	   "\t\t[--interval=SECONDS] HOSTNAME\n", argv[0]);
    exit(0);
  }
  if (Hostname == NULL) Hostname = "localhost";

  if(gethostname(LocalHostname, sizeof(LocalHostname))) {
	strcpy(LocalHostname, "UNKNOWNHOST");
  }

  if(net_preopen_result != 0) {
    printf("mtr: Unable to get raw socket.  (Executable not suid?)\n");
    exit(1);
  }


  host = gethostbyname(Hostname);
  if(host == NULL) {
#ifndef NO_HERROR
    herror("mtr");
#else
    printf("mtr: error looking up \"%s\"\n", Hostname);
#endif
    exit(1);
  }

  traddr = *(int *)host->h_addr;

  if(net_open(traddr) != 0) {
    printf("mtr: Unable to get raw socket.  (Executable not suid?)\n");
    exit(1);
  }

  display_open();
  dns_open();

  display_mode = 0;
  display_loop();

  net_end_transit();
  display_close();
  net_close();

  return 0;
}


