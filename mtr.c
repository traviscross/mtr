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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "mtr.h"
#include "mtr-curses.h"
#include "getopt.h"
#include "display.h"
#include "dns.h"
#include "report.h"
#include "net.h"
#include "asn.h"
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
float GraceTime = 5.0;
char *Hostname = NULL;
char *InterfaceAddress = NULL;
char  LocalHostname[128];
int   dns = 1;
int   show_ips = 0;
int   enablempls = 0;
int   cpacketsize = 64;          /* default packet size */
int   bitpattern = 0;
int   tos = 0;
#ifdef SO_MARK
int   mark = -1;
#endif
int   reportwide = 0;
int af = DEFAULT_AF;
int mtrtype = IPPROTO_ICMP;     /* Use ICMP as default packet type */

                                /* begin ttl windows addByMin */
int  fstTTL = 1;                /* default start at first hop */
/*int maxTTL = MaxHost-1;  */     /* max you can go is 255 hops */
int   maxTTL = 30;              /* inline with traceroute */
                                /* end ttl window stuff. */
int maxUnknown = 12;            /* stop send package */
                                /* when larger than this count */
int remoteport = 0;            /* for TCP tracing */
int localport = 0;             /* for UDP tracing */
int tcp_timeout = 10 * 1000000;     /* for TCP tracing */


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

typedef struct names {
  char*                 name;
  struct names*         next;
} names_t;
static names_t *names = NULL;

char *
trim(char * s) {

  char * p = s;
  int l = strlen(p);

  while(isspace(p[l-1]) && l) p[--l] = 0;
  while(*p && isspace(*p) && l) ++p, --l;

  return p;
}

static void
append_to_names(const char* progname, const char* item) {

  names_t* name = calloc(1, sizeof(names_t));
  if (name == NULL) {
    fprintf(stderr, "%s: memory allocation failure\n", progname);
    exit(EXIT_FAILURE);
  }
  name->name = strdup(item);
  name->next = names;
  names = name;
}

static void
read_from_file(const char* progname, const char *filename) {

  FILE *in;
  char line[512];

  if (! filename || strcmp(filename, "-") == 0) {
    clearerr(stdin);
    in = stdin;
  } else {
    in = fopen(filename, "r");
    if (! in) {
      fprintf(stderr, "%s: fopen: %s\n", progname, strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  while (fgets(line, sizeof(line), in)) {
    char* name = trim(line);
    append_to_names(progname, name);
  }

  if (ferror(in)) {
    fprintf(stderr, "%s: ferror: %s\n", progname, strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (in != stdin) fclose(in);
}

/*
 * If the file stream is associated with a regular file, lock the file
 * in order coordinate writes to a common file from multiple mtr
 * instances. This is useful if, for example, multiple mtr instances
 * try to append results to a common file.
 */

static void
lock(const char* progname, FILE *f) {
    int fd;
    struct stat buf;
    static struct flock lock;

    assert(f);

    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_END;
    lock.l_len = 0;
    lock.l_pid = getpid();

    fd = fileno(f);
    if ((fstat(fd, &buf) == 0) && S_ISREG(buf.st_mode)) {
      if (fcntl(fd, F_SETLKW, &lock) == -1) {
          fprintf(stderr, "%s: fcntl: %s (ignored)\n",
            progname, strerror(errno));
      }
    }
}

/*
 * If the file stream is associated with a regular file, unlock the
 * file (which presumably has previously been locked).
 */

static void
unlock(const char* progname, FILE *f) {
    int fd;
    struct stat buf;
    static struct flock lock;

    assert(f);

    lock.l_type = F_UNLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_END;
    lock.l_len = 0;
    lock.l_pid = getpid();

    fd = fileno(f);
    if ((fstat(fd, &buf) == 0) && S_ISREG(buf.st_mode)) {
      if (fcntl(fd, F_SETLKW, &lock) == -1) {
          fprintf(stderr, "%s: fcntl: %s (ignored)\n",
            progname, strerror(errno));
      }
    }
}


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
  /* IMPORTANT: when adding or modifying an option:
       0/ try to find a somewhat logical order;
       1/ add the long option name in "long_options" below;
       2/ add the short option name in the "getopt_long" call;
       3/ update the man page (use the same order);
       4/ update the help message (see PrintHelp).
   */
  static struct option long_options[] = {
    /* option name, has argument, NULL, short name */
    { "help",           0, NULL, 'h' },
    { "version",        0, NULL, 'v' },

    { "inet",           0, NULL, '4' }, /* IPv4 only */
    { "inet6",          0, NULL, '6' }, /* IPv6 only */

    { "filename",       1, NULL, 'F' },

    { "report",         0, NULL, 'r' },
    { "report-wide",    0, NULL, 'w' },
    { "xml",            0, NULL, 'x' },
    { "curses",         0, NULL, 't' },
    { "gtk",            0, NULL, 'g' },
    { "raw",            0, NULL, 'l' },
    { "csv",            0, NULL, 'C' },
    { "json",           0, NULL, 'j' },
    { "displaymode",    1, NULL, 'd' },
    { "split",          0, NULL, 'p' }, /* BL */
                                        /* maybe above should change to -d 'x' */

    { "no-dns",         0, NULL, 'n' },
    { "show-ips",       0, NULL, 'b' },
    { "order",          1, NULL, 'o' }, /* fields to display & their order */
#ifdef IPINFO
    { "ipinfo",         1, NULL, 'y' }, /* IP info lookup */
    { "aslookup",       0, NULL, 'z' }, /* Do AS lookup (--ipinfo 0) */
#endif

    { "interval",       1, NULL, 'i' },
    { "report-cycles",  1, NULL, 'c' },
    { "psize",          1, NULL, 's' }, /* overload psize<0, ->rand(min,max) */
    { "bitpattern",     1, NULL, 'B' }, /* overload B>255, ->rand(0,255) */
    { "tos",            1, NULL, 'Q' }, /* typeof service (0,255) */
    { "mpls",           0, NULL, 'e' },
    { "address",        1, NULL, 'a' },
    { "first-ttl",      1, NULL, 'f' }, /* -f & -m are borrowed from traceroute */
    { "max-ttl",        1, NULL, 'm' },
	{ "max-unknown",    1, NULL, 'U' },
    { "udp",            0, NULL, 'u' }, /* UDP (default is ICMP) */
    { "tcp",            0, NULL, 'T' }, /* TCP (default is ICMP) */
    { "sctp",           0, NULL, 'S' }, /* SCTP (default is ICMP) */
    { "port",           1, NULL, 'P' }, /* target port number for TCP/SCTP/UDP */
    { "localport",      1, NULL, 'L' }, /* source port number for UDP */
    { "timeout",        1, NULL, 'Z' }, /* timeout for TCP sockets */
    { "gracetime",      1, NULL, 'G' }, /* graceperiod for replies after last probe */
#ifdef SO_MARK
    { "mark",           1, NULL, 'M' }, /* use SO_MARK */
#endif
    { 0, 0, 0, 0 }
  };

  opt = 0;
  while(1) {
    opt = getopt_long(argc, argv,
		      "hv46F:rwxtglCjpnbo:y:zi:c:s:B:Q:ea:f:m:U:uTSP:L:Z:G:M:", long_options, NULL);
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
    case 'j':
      DisplayMode = DisplayJSON;
      break;
    case 'x':
      DisplayMode = DisplayXML;
      break;

    case 'd':
      display_mode = (atoi (optarg)) % 3;
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
    case 'F':
      read_from_file(argv[0], optarg);
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
	case 'U':
		maxUnknown = atoi(optarg);
		if (maxUnknown < 1) {
			maxUnknown = 1;
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
    case 'G':
      GraceTime = atof (optarg);
      if (GraceTime <= 0.0) {
        fprintf (stderr, "mtr: wait time must be positive\n");
        exit (1);
      }
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
        fprintf(stderr, "-u , -T and -S are mutually exclusive.\n");
        exit(EXIT_FAILURE);
      }
      mtrtype = IPPROTO_UDP;
      break;
    case 'T':
      if (mtrtype != IPPROTO_ICMP) {
        fprintf(stderr, "-u , -T and -S are mutually exclusive.\n");
        exit(EXIT_FAILURE);
      }
      if (!remoteport) {
        remoteport = 80;
      }
      mtrtype = IPPROTO_TCP;
      break;
    case 'S':
      if (mtrtype != IPPROTO_ICMP) {
        fprintf(stderr, "-u , -T and -S are mutually exclusive.\n");
        exit(EXIT_FAILURE);
      }
      if (!remoteport) {
        remoteport = 80;
      }
      mtrtype = IPPROTO_SCTP;
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
    case 'L':
      localport = atoi(optarg);
      if (localport > 65535 || localport < MinPort) {
        fprintf(stderr, "Illegal local port number.\n");
        exit(EXIT_FAILURE);
      }
      break;
    case 'Z':
      tcp_timeout = atoi(optarg);
      tcp_timeout *= 1000000;
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
#ifdef IPINFO
    case 'y':
      ipinfo_no = atoi (optarg);
      if (ipinfo_no < 0)
        ipinfo_no = 0;
      break;
    case 'z':
      ipinfo_no = 0;
      break;
#else
    case 'y':
    case 'z':
      fprintf( stderr, "IPINFO not enabled.\n" );
      break;
#endif
#ifdef SO_MARK
    case 'M':
      mark = atoi (optarg);
      if (mark < 0) {
        fprintf( stderr, "SO_MARK must be positive.\n" );
        exit(EXIT_FAILURE);
      }
      break;
#else
    case 'M':
      fprintf( stderr, "SO_MARK not enabled.\n" );
      break;
#endif
    }
  }

  if (DisplayMode == DisplayReport ||
      DisplayMode == DisplayTXT ||
      DisplayMode == DisplayJSON ||
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
  display_mode = 0;

  /* The field options are now in a static array all together,
     but that requires a run-time initialization. */
  init_fld_options ();

  parse_mtr_options (getenv ("MTR_OPTIONS"));

  parse_arg (argc, argv);

  while (optind < argc) {
    char* name = argv[optind++];
    append_to_names(argv[0], name);
  }

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
       printf("usage: %s [--help] [--version] [-4|-6] [-F FILENAME]\n"
              "\t\t[--report] [--report-wide] [--displaymode MODE]\n"
              "\t\t[--xml] [--gtk] [--curses] [--raw] [--csv] [--json] [--split]\n"
              "\t\t[--no-dns] [--show-ips] [-o FIELDS] [-y IPINFO] [--aslookup]\n"
              "\t\t[-i INTERVAL] [-c COUNT] [-s PACKETSIZE] [-B BITPATTERN]\n"
              "\t\t[-Q TOS] [--mpls]\n"
              "\t\t[-a ADDRESS] [-f FIRST-TTL] [-m MAX-TTL] [-U MAX_UNKNOWN]\n"
              "\t\t[--udp] [--tcp] [--sctp] [-P PORT] [-L LOCALPORT] [-Z TIMEOUT]\n"
              "\t\t[-G GRACEPERIOD] [-M MARK] HOSTNAME\n", argv[0]);
       printf("See the man page for details.\n");
    exit(0);
  }

  time_t now = time(NULL);

  if (!names) append_to_names (argv[0], "localhost"); // default: localhost. 

  names_t* head = names;
  while (names != NULL) {

    Hostname = names->name;
    //  if (Hostname == NULL) Hostname = "localhost"; // no longer necessary.
    if (gethostname(LocalHostname, sizeof(LocalHostname))) {
      strcpy(LocalHostname, "UNKNOWNHOST");
    }

    if (net_preopen_result != 0) {
      fprintf(stderr, "mtr: Unable to get raw socket.  (Executable not suid?)\n");
      if ( DisplayMode != DisplayCSV ) exit(EXIT_FAILURE);
      else {
        names = names->next;
        continue;
      }
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

      if ( DisplayMode != DisplayCSV ) exit(EXIT_FAILURE);
      else {
        names = names->next;
        continue;
      }
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
      if ( DisplayMode != DisplayCSV ) exit(EXIT_FAILURE);
      else {
        names = names->next;
        continue;
      }
    }
    alptr[1] = NULL;
#else
      host = gethostbyname(Hostname);
    if (host == NULL) {
      herror("mtr gethostbyname");
      if ( DisplayMode != DisplayCSV ) exit(EXIT_FAILURE);
      else {
        names = names->next;
        continue;
      }
    }
    af = host->h_addrtype;
#endif

    if (net_open(host) != 0) {
      fprintf(stderr, "mtr: Unable to start net module.\n");
      if ( DisplayMode != DisplayCSV ) exit(EXIT_FAILURE);
      else {
        names = names->next;
        continue;
      }
    }

    if (net_set_interfaceaddress (InterfaceAddress) != 0) {
      fprintf( stderr, "mtr: Couldn't set interface address.\n" );
      if ( DisplayMode != DisplayCSV ) exit(EXIT_FAILURE);
      else {
        names = names->next;
        continue;
      }
    }


    lock(argv[0], stdout);
      display_open();
      dns_open();

      display_loop();

      net_end_transit();
      display_close(now);
    unlock(argv[0], stdout);

    if ( DisplayMode != DisplayCSV ) break;
    else names = names->next;

  }

  net_close();

  while (head != NULL) {
    names_t* item = head;
    free(item->name); item->name = NULL;
    head = head->next;
    free(item); item = NULL;
  }
  head=NULL;

  return 0;
}
