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

#include <sys/types.h>
#include <config.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h> 
#include <unistd.h>
#include <strings.h>
#include <time.h>

#include "mtr.h"
#include "mtr-curses.h"
#include "getopt.h"
#include "display.h"
#include "dns.h"
#include "report.h"
#include "net.h"
#ifndef NO_IPINFO
#include "asn.h"
#endif
#include "version.h"


#ifdef ENABLE_IPV6
#define DEFAULT_AF AF_UNSPEC
#else
#define DEFAULT_AF AF_INET
#endif


#ifdef NO_HERROR
#define herror(str) fprintf(stderr, str ": error looking up \"%s\"\n", Hostname);
#endif


int   DisplayMode;
int   display_mode;
int   Interactive = 1;
int   PrintVersion = 0;
int   PrintHelp = 0;
int   MaxPing = 10;
int   ForceMaxPing = 0;
float WaitTime = 1.0;
char *Hostname = NULL;
char *InterfaceAddress = NULL;
char  LocalHostname[128];
int   dns = 1;
int   show_ips = 0;
int   enablempls = 0;
int   cpacketsize = 64;          /* default packet size */
int   bitpattern = 0;
int   tos = 0;
int   reportwide = 0;
int af = DEFAULT_AF;
int mtrtype = IPPROTO_ICMP;     /* Use ICMP as default packet type */

                                /* begin ttl windows addByMin */
int  fstTTL = 1;                /* default start at first hop */
/*int maxTTL = MaxHost-1;  */     /* max you can go is 255 hops */
int   maxTTL = 30;              /* inline with traceroute */
                                /* end ttl window stuff. */
int remoteport = 80;            /* for TCP tracing */
int timeout = 10 * 1000000;     /* for TCP tracing */


/* default display field(defined by key in net.h) and order */
unsigned char fld_active[2*MAXFLD] = "LS NABWV";
int           fld_index[256];
char          available_options[MAXFLD];


struct fields data_fields[MAXFLD] = {
  /* key, Remark, Header, Format, Width, CallBackFunc */
  {' ', "<sp>: Space between fields", " ",  " ",        1, &net_drop  },
  {'L', "L: Loss Ratio",          "Loss%",  " %4.1f%%", 6, &net_loss  },
  {'D', "D: Dropped Packets",     "Drop",   " %4d",     5, &net_drop  },
  {'R', "R: Received Packets",    "Rcv",    " %5d",     6, &net_returned},
  {'S', "S: Sent Packets",        "Snt",    " %5d",     6, &net_xmit  },
  {'N', "N: Newest RTT(ms)",      "Last",   " %5.1f",   6, &net_last  },
  {'B', "B: Min/Best RTT(ms)",    "Best",   " %5.1f",   6, &net_best  },
  {'A', "A: Average RTT(ms)",     "Avg",    " %5.1f",   6, &net_avg   },
  {'W', "W: Max/Worst RTT(ms)",   "Wrst",   " %5.1f",   6, &net_worst },
  {'V', "V: Standard Deviation",  "StDev",  " %5.1f",   6, &net_stdev },
  {'G', "G: Geometric Mean",      "Gmean",  " %5.1f",   6, &net_gmean },
  {'J', "J: Current Jitter",      "Jttr",   " %4.1f",   5, &net_jitter},
  {'M', "M: Jitter Mean/Avg.",    "Javg",   " %4.1f",   5, &net_javg  },
  {'X', "X: Worst Jitter",        "Jmax",   " %4.1f",   5, &net_jworst},
  {'I', "I: Interarrival Jitter", "Jint",   " %4.1f",   5, &net_jinta },
  {'\0', NULL, NULL, NULL, 0, NULL}
};


void init_fld_options (void)
{
  int i;

  for (i=0;i < 256;i++)
    fld_index[i] = -1;

  for (i=0;data_fields[i].key != 0;i++) {
    available_options[i] = data_fields[i].key;
    fld_index[data_fields[i].key] = i;
  }
  available_options[i] = 0;
}


void parse_arg (int argc, char **argv) 
{
  int opt;
  int i;
  static struct option long_options[] = {
    { "version", 0, 0, 'v' },
    { "help", 0, 0, 'h' },

    { "report", 0, 0, 'r' },
    { "report-wide", 0, 0, 'w' },
    { "xml", 0, 0, 'x' },
    { "curses", 0, 0, 't' },
    { "gtk", 0, 0, 'g' },
    { "raw", 0, 0, 'l' },
    { "csv", 0, 0, 'C' },
    { "split", 0, 0, 'p' },     /* BL */
    				/* maybe above should change to -d 'x' */

    { "order", 1, 0, 'o' },	/* fileds to display & their order */

    { "interval", 1, 0, 'i' },
    { "report-cycles", 1, 0, 'c' },
    { "psize", 1, 0, 's' },	/* changed 'p' to 's' to match ping option
				   overload psize<0, ->rand(min,max) */
    { "bitpattern", 1, 0, 'B' },/* overload b>255, ->rand(0,255) */
    { "tos", 1, 0, 'Q' },	/* typeof service (0,255) */
    { "mpls", 0, 0, 'e' },
    { "no-dns", 0, 0, 'n' },
    { "show-ips", 0, 0, 'b' },
    { "address", 1, 0, 'a' },
    { "first-ttl", 1, 0, 'f' },	/* -f & -m are borrowed from traceroute */
    { "max-ttl", 1, 0, 'm' },
    { "udp", 0, 0, 'u' },	/* UDP (default is ICMP) */
    { "tcp", 0, 0, 'T' },	/* TCP (default is ICMP) */
    { "port", 1, 0, 'P' },      /* target port number for TCP */
    { "timeout", 1, 0, 'Z' },   /* timeout for TCP sockets */
    { "inet", 0, 0, '4' },	/* IPv4 only */
    { "inet6", 0, 0, '6' },	/* IPv6 only */
#ifndef NO_IPINFO
    { "ipinfo", 1, 0, 'y' },    /* IP info lookup */
    { "aslookup", 0, 0, 'z' },  /* Do AS lookup (--ipinfo 0) */
#endif
    { 0, 0, 0, 0 }
  };

  opt = 0;
  while(1) {
    /* added f:m:o: byMin */
    opt = getopt_long(argc, argv,
		      "vhrwxtglCpo:B:i:c:s:Q:ena:f:m:uTP:Zby:z46", long_options, NULL);
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
    case 'w':
      reportwide = 1;
      DisplayMode = DisplayReport;
      break;
    case 't':
      DisplayMode = DisplayCurses;
      break;
    case 'g':
      DisplayMode = DisplayGTK;
      break;
    case 'p':                 /* BL */
      DisplayMode = DisplaySplit;
      break;
    case 'l':
      DisplayMode = DisplayRaw;
      break;
    case 'C':
      DisplayMode = DisplayCSV;
      break;
    case 'x':
      DisplayMode = DisplayXML;
      break;

    case 'c':
      MaxPing = atoi (optarg);
      ForceMaxPing = 1;
      break;
    case 's':
      cpacketsize = atoi (optarg);
      break;
    case 'a':
      InterfaceAddress = optarg;
      break;
    case 'e':
      enablempls = 1;
      break;
    case 'n':
      dns = 0;
      break;
    case 'i':
      WaitTime = atof (optarg);
      if (WaitTime <= 0.0) {
	fprintf (stderr, "mtr: wait time must be positive\n");
	exit (1);
      }
      if (getuid() != 0 && WaitTime < 1.0) {
        fprintf (stderr, "non-root users cannot request an interval < 1.0 seconds\r\n");
	exit (1);
      }
      break;
    case 'f':
      fstTTL = atoi (optarg);
      if (fstTTL > maxTTL) {
	fstTTL = maxTTL;
      }
      if (fstTTL < 1) {                       /* prevent 0 hop */
	fstTTL = 1;
      }
      break;
    case 'm':
      maxTTL = atoi (optarg);
      if (maxTTL > (MaxHost - 1)) {
	maxTTL = MaxHost-1;
      }
      if (maxTTL < 1) {                       /* prevent 0 hop */
	maxTTL = 1;
      }
      if (fstTTL > maxTTL) {         /* don't know the pos of -m or -f */
	fstTTL = maxTTL;
      }
      break;
    case 'o':
      /* Check option before passing it on to fld_active. */
      if (strlen (optarg) > MAXFLD) {
	fprintf (stderr, "Too many fields: %s\n", optarg);
        exit (1);
      }
      for (i=0; optarg[i]; i++) {
        if(!strchr (available_options, optarg[i])) {
          fprintf (stderr, "Unknown field identifier: %c\n", optarg[i]);
          exit (1);
        }
      }
      strcpy ((char*)fld_active, optarg);
      break;
    case 'B':
      bitpattern = atoi (optarg);
      if (bitpattern > 255)
	bitpattern = -1;
      break;
    case 'Q':
      tos = atoi (optarg);
      if (tos > 255 || tos < 0) {
	/* error message, should do more checking for valid values,
	 * details in rfc2474 */
	tos = 0;
      }
      break;
    case 'u':
      if (mtrtype != IPPROTO_ICMP) {
        fprintf(stderr, "-u and -T are mutually exclusive.\n");
        exit(EXIT_FAILURE);
      }
      mtrtype = IPPROTO_UDP;
      break;
    case 'T':
      if (mtrtype != IPPROTO_ICMP) {
        fprintf(stderr, "-u and -T are mutually exclusive.\n");
        exit(EXIT_FAILURE);
      }
      mtrtype = IPPROTO_TCP;
      break;
    case 'b':
      show_ips = 1;
      break;
    case 'P':
      remoteport = atoi(optarg);
      if (remoteport > 65535 || remoteport < 1) {
        fprintf(stderr, "Illegal port number.\n");
        exit(EXIT_FAILURE);
      }
      break;
    case 'Z':
      timeout = atoi(optarg);
      timeout *= 1000000;
      break;
    case '4':
      af = AF_INET;
      break;
    case '6':
#ifdef ENABLE_IPV6
      af = AF_INET6;
      break;
#else
      fprintf( stderr, "IPv6 not enabled.\n" );
      break;
#endif
#ifndef NO_IPINFO
    case 'y':
      ipinfo_no = atoi (optarg);
      if (ipinfo_no < 0)
        ipinfo_no = 0;
      break;
    case 'z':
      ipinfo_no = 0;
      break;
#endif
    }
  }

  if (DisplayMode == DisplayReport ||
      DisplayMode == DisplayTXT ||
      DisplayMode == DisplayXML ||
      DisplayMode == DisplayRaw ||
      DisplayMode == DisplayCSV)
    Interactive = 0;

  if (optind > argc - 1)
    return;

}


void parse_mtr_options (char *string)
{
  int argc;
  char *argv[128], *p;

  if (!string) return;

  argv[0] = "mtr";
  argc = 1;
  p = strtok (string, " \t");
  while (p != NULL && ((size_t) argc < (sizeof(argv)/sizeof(argv[0])))) {
    argv[argc++] = p;
    p = strtok (NULL, " \t");
  }
  if (p != NULL) {
    fprintf (stderr, "Warning: extra arguments ignored: %s", p);
  }

  parse_arg (argc, argv);
  optind = 0;
}


int main(int argc, char **argv) 
{
  struct hostent *  host                = NULL;
  int               net_preopen_result;
#ifdef ENABLE_IPV6
  struct addrinfo       hints, *res;
  int                   error;
  struct hostent        trhost;
  char *                alptr[2];
  struct sockaddr_in *  sa4;
  struct sockaddr_in6 * sa6;
#endif

  /*  Get the raw sockets first thing, so we can drop to user euid immediately  */

  if ( ( net_preopen_result = net_preopen () ) ) {
    fprintf( stderr, "mtr: unable to get raw sockets.\n" );
    exit( EXIT_FAILURE );
  }

  /*  Now drop to user permissions  */
  if (setgid(getgid()) || setuid(getuid())) {
    fprintf (stderr, "mtr: Unable to drop permissions.\n");
    exit(1);
  }

  /*  Double check, just in case  */
  if ((geteuid() != getuid()) || (getegid() != getgid())) {
    fprintf (stderr, "mtr: Unable to drop permissions.\n");
    exit(1);
  }

  /* reset the random seed */
  srand (getpid());
  
  display_detect(&argc, &argv);

  /* The field options are now in a static array all together, 
     but that requires a run-time initialization. */
  init_fld_options ();

  parse_mtr_options (getenv ("MTR_OPTIONS"));

  parse_arg (argc, argv);

  /* Now that we know mtrtype we can select which socket to use */
  if (net_selectsocket() != 0) {
    fprintf( stderr, "mtr: Couldn't determine raw socket type.\n" );
    exit( EXIT_FAILURE );
  }

  if (PrintVersion) {
    printf ("mtr " MTR_VERSION "\n");
    exit(0);
  }

  if (PrintHelp) {
    printf("usage: %s [-hvrwctglspniuT46] [--help] [--version] [--report]\n"
	   "\t\t[--report-wide] [--report-cycles=COUNT] [--curses] [--gtk]\n"
           "\t\t[--raw] [--split] [--mpls] [--no-dns] [--show-ips]\n"
           "\t\t[--address interface]\n" /* BL */
#ifndef NO_IPINFO
           "\t\t[--ipinfo=item_no|-y item_no]\n"
           "\t\t[--aslookup|-z]\n"
#endif
           "\t\t[--psize=bytes/-s bytes]\n"            /* ok */
           "\t\t[--report-wide|-w] [-u|-T] [--port=PORT] [--timeout=SECONDS]\n"            /* rew */
	   "\t\t[--interval=SECONDS] HOSTNAME\n", argv[0]);
    exit(0);
  }

  time_t now = time(NULL);

  while (optind < argc ) {

    Hostname = argv[optind++];
    if (Hostname == NULL) Hostname = "localhost";
    if (gethostname(LocalHostname, sizeof(LocalHostname))) {
    strcpy(LocalHostname, "UNKNOWNHOST");
    }

    if (net_preopen_result != 0) {
      fprintf(stderr, "mtr: Unable to get raw socket.  (Executable not suid?)\n");
      exit(1);
    }

#ifdef ENABLE_IPV6
    /* gethostbyname2() is deprecated so we'll use getaddrinfo() instead. */
    bzero( &hints, sizeof hints );
    hints.ai_family = af;
    hints.ai_socktype = SOCK_DGRAM;
    error = getaddrinfo( Hostname, NULL, &hints, &res );
    if ( error ) {
      if (error == EAI_SYSTEM)
         perror ("Failed to resolve host");
      else
         fprintf (stderr, "Failed to resolve host: %s\n", gai_strerror(error));
      exit( EXIT_FAILURE );
    }
    /* Convert the first addrinfo into a hostent. */
    host = &trhost;
    bzero( host, sizeof trhost );
    host->h_name = res->ai_canonname;
    host->h_aliases = NULL;
    host->h_addrtype = res->ai_family;
    af = res->ai_family;
    host->h_length = res->ai_addrlen;
    host->h_addr_list = alptr;
    switch ( af ) {
    case AF_INET:
      sa4 = (struct sockaddr_in *) res->ai_addr;
      alptr[0] = (void *) &(sa4->sin_addr);
      break;
    case AF_INET6:
      sa6 = (struct sockaddr_in6 *) res->ai_addr;
      alptr[0] = (void *) &(sa6->sin6_addr);
      break;
    default:
      fprintf( stderr, "mtr unknown address type\n" );
      exit( EXIT_FAILURE );
    }
    alptr[1] = NULL;
#else
      host = gethostbyname(Hostname);
    if (host == NULL) {
      herror("mtr gethostbyname");
      exit(1);
    }
    af = host->h_addrtype;
#endif

    if (net_open(host) != 0) {
    fprintf(stderr, "mtr: Unable to start net module.\n");
          exit(1);
        }

    if (net_set_interfaceaddress (InterfaceAddress) != 0) {
      fprintf( stderr, "mtr: Couldn't set interface address.\n" ); 
      exit( EXIT_FAILURE ); 
    }

    display_open();
    dns_open();

    display_mode = 0;
    display_loop();

    net_end_transit();
    display_close(now);

    if ( DisplayMode != DisplayCSV ) break;

  }

  net_close();

  return 0;
}


