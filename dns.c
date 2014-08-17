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

/*
    Non-blocking DNS portion --
    Copyright (C) 1998 by Simon Kirby <sim@neato.org>
    Released under GPL, as above.
*/

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef __APPLE__
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#include <netdb.h>
#include <resolv.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "mtr.h"
#include "dns.h"
#include "net.h"

extern int af;


int use_dns = 1;


struct dns_results {
  ip_t ip; 
  char *name;
  struct dns_results *next;
};

struct dns_results *results;

char *strlongip(ip_t * ip)
{
#ifdef ENABLE_IPV6
  static char addrstr[INET6_ADDRSTRLEN];

  return (char *) inet_ntop( af, ip, addrstr, sizeof addrstr );
#else
  return inet_ntoa( *ip );
#endif
}


int longipstr( char *s, ip_t *dst, int af )
{
#ifdef ENABLE_IPV6
  return inet_pton( af, s, dst );
#else
  return inet_aton( s, dst );
#endif
}


struct hostent * dns_forward(const char *name)
{
  struct hostent *host;

  if ((host = gethostbyname(name)))
    return host;
  else
    return NULL;
}


struct dns_results *findip (ip_t *ip)
{
  struct dns_results *t;
  
  //printf ("Looking for: %s\n",  strlongip (ip));
  for (t=results;t;t=t->next) {
    //printf ("comparing: %s\n",  strlongip (&t->ip));
    if (addrcmp ( (void *)ip, (void*) &t->ip, af) == 0)
      return t;
  }

  return NULL;
}

void set_sockaddr_ip (struct sockaddr *sa, ip_t *ip)
{
  struct sockaddr_in *sa_in;
  struct sockaddr_in6 *sa_in6;

  sa->sa_family = af;
  switch (af) {
  case AF_INET:
    sa_in = (struct sockaddr_in *) sa;
    addrcpy ((void *) &sa_in->sin_addr, (void*) ip, af);
    break;
  case AF_INET6:
    sa_in6 = (struct sockaddr_in6 *) sa;
    addrcpy ((void *) &sa_in6->sin6_addr,  (void*)ip, af);
    break;
  }
}


static int todns[2], fromdns[2];
FILE *fromdnsfp;

#if 0
void handle_sigchld(int sig) {
  while (waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
}
#endif

void dns_open(void)
{
  int pid; 
 
  if (pipe (todns) < 0) {
    perror ("can't make a pipe for DNS process");
    exit (-1);
  }

  if (pipe (fromdns) < 0) {
    perror ("can't make a pipe for DNS process");
    exit (-1);
  }

  pid = fork ();
  //pid = 1;
  if (pid < 0) {
    perror ("can't fork for DNS process");
    exit (-1);
  }
  if (pid == 0) {
    char buf[1024];
    int i;
    FILE *infp; //, *outfp;

    // Automatically reap children. 
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
      perror("signal");
      exit(1);
    }

#if 0
    // No longer necessary: we close all of them below.
    // The child: We're going to handle the DNS requests here. 
    close (todns[1]); // close the pipe ends we don't need. 
    close (fromdns[0]);
#endif
    // Close all unneccessary FDs.
    // for debugging and error reporting, keep std-in/out/err.
    for (i=3;i<fromdns[1];i++) {
       if (i == todns[0]) continue;
       if (i == fromdns[1]) continue;
       close (i);
    }
    infp = fdopen (todns[0],"r"); 
    //outfp = fdopen (fromdns[1],"w"); 

    while (fgets (buf, 1024, infp)) {
      ip_t host; 
      struct sockaddr sa;
      char hostname [0x100];
      char result [0x100];
      // Find IPV6 version
      if (!fork ()) {
        int rv;

        buf[strlen(buf)-1] = 0; // chomp newline.

        longipstr (buf, &host, af);

        printf ("resolving %s (%d)\n", strlongip (&host), af);

        set_sockaddr_ip (&sa, &host);

        rv = getnameinfo  (&sa, sizeof  (sa), 
			       hostname, 0x100, NULL, 0, 0);

        sprintf (result, "%s %s\n", strlongip (&host), hostname);

        printf ("resolved: %s -> %s (%d)\n", strlongip (&host), hostname, rv);

        write (fromdns[1], result, strlen (result));
        exit (0);
      }
    }
    exit (0);
  } else {
     int flags;

     // the parent. 
     close (todns[0]); // close the pipe ends we don't need. 
     close (fromdns[1]);
     fromdnsfp = fdopen (fromdns[0],"r"); 
     flags = fcntl(fromdns[0], F_GETFL, 0);
     flags |= O_NONBLOCK;
     fcntl(fromdns[0], F_SETFL, flags);
  }
}

int dns_waitfd (void)
{
  return fromdns[0];
}



void dns_ack(void)
{
  char buf[0x100], host[0x100], name[0x100];  
  ip_t hostip; 
  struct dns_results *r;

     //read (fromdns[0], buf, 0x100);
  while ( fgets (buf, 0x100,  fromdnsfp )) {
    sscanf (buf, "%s %s", host, name);

    longipstr (host, &hostip, af);
    r = findip (&hostip);
    if (r)  
      r->name = strdup (name);
    else 
      fprintf (stderr, "dns_ack: Couldn't find host %s\n", host);
  }
}



#ifdef ENABLE_IPV6

int dns_waitfd6 (void)
{
  return  -1;
}

void dns_ack6(void)
{
  return;
}

#endif


char *dns_lookup2(ip_t * ip)
{
  struct dns_results *r;
  char buf[0x100];
   
  r = findip (ip);
  if (r) {
     // we've got a result. 
     if (r->name) 
        return r->name;
     else
        return strlongip (ip);
  } else {
     r = malloc (sizeof (struct dns_results));
     //r->ip = *ip;
     memcpy (&r->ip, ip, sizeof (r->ip));
     r->name = NULL;
     r->next = results;
     results = r;

     printf ("lookup: %s\n", strlongip (ip));

     sprintf (buf, "%s\n", strlongip (ip));
     write  (todns[1], buf, strlen (buf));
  }
  return strlongip (ip);
}


void dns_events(double *sinterval)
{
  return;
}


char *dns_lookup(ip_t * ip)
{
  char *t;

  if (!dns) return NULL;
  t = dns_lookup2(ip);
  return (t && use_dns) ? t : NULL;
}


#if 0
char *strlongip(ip_t * ip)
{
#ifdef ENABLE_IPV6
  static char addrstr[INET6_ADDRSTRLEN];

  return (char *) inet_ntop( af, ip, addrstr, sizeof addrstr );
#else
  return inet_ntoa( *ip );
#endif
}
#endif


// XXX check if necessary/exported. 

/* Resolve an IP address to a hostname. */ 
struct hostent *addr2host( const char *addr, int af ) {
  int len = 0;
  switch ( af ) {
  case AF_INET:
    len = sizeof( struct in_addr );
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    len = sizeof( struct in6_addr );
    break;
#endif
  }
  return gethostbyaddr( addr, len, af );
}



