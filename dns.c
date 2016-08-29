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

#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "mtr.h"
#include "dns.h"
#include "net.h"
#include "utils.h"

struct dns_results {
  ip_t ip; 
  char *name;
  struct dns_results *next;
};

struct dns_results *results;

extern char *strlongip(struct mtr_ctl *ctl, ip_t * ip)
{
#ifdef ENABLE_IPV6
  static char addrstr[INET6_ADDRSTRLEN];

  return (char *) inet_ntop( ctl->af, ip, addrstr, sizeof addrstr );
#else
  return inet_ntoa( *ip );
#endif
}


#ifdef ENABLE_IPV6
#define UNUSED_IF_NO_IPV6
#else
#define UNUSED_IF_NO_IPV6 UNUSED
#endif

static int longipstr( char *s, ip_t *dst, int family UNUSED_IF_NO_IPV6)
{
#ifdef ENABLE_IPV6
  return inet_pton( family, s, dst );
#else
  return inet_aton( s, dst );
#endif
}


extern struct hostent * dns_forward(const char *name)
{
  struct hostent *host;

  if ((host = gethostbyname(name)))
    return host;
  else
    return NULL;
}


static struct dns_results *findip (struct mtr_ctl *ctl, ip_t *ip)
{
  struct dns_results *t;
  
  //printf ("Looking for: %s\n",  strlongip (ctl, ip));
  for (t=results;t;t=t->next) {
    //printf ("comparing: %s\n",  strlongip (ctl, &t->ip));
    if (addrcmp ( (void *)ip, (void*) &t->ip, ctl->af) == 0)
      return t;
  }

  return NULL;
}

static void set_sockaddr_ip (struct mtr_ctl *ctl, struct sockaddr_storage *sa, ip_t *ip)
{
  struct sockaddr_in *sa_in;
  struct sockaddr_in6 *sa_in6;

  memset (sa, 0, sizeof (struct sockaddr_storage));
  switch (ctl->af) {
  case AF_INET:
    sa_in = (struct sockaddr_in *) sa;
    sa_in->sin_family = ctl->af;
    addrcpy ((void *) &sa_in->sin_addr, (void*) ip, ctl->af);
    break;
  case AF_INET6:
    sa_in6 = (struct sockaddr_in6 *) sa;
    sa_in6->sin6_family = ctl->af;
    addrcpy ((void *) &sa_in6->sin6_addr,  (void*)ip, ctl->af);
    break;
  }
}


static int todns[2], fromdns[2];
FILE *fromdnsfp;

#if 0
static void handle_sigchld(int sig) {
  while (waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
}
#endif

extern void dns_open(struct mtr_ctl *ctl)
{
  int pid; 
 
  if (pipe (todns) < 0) {
    error(EXIT_FAILURE, errno, "can't make a pipe for DNS process");
  }

  if (pipe (fromdns) < 0) {
    error(EXIT_FAILURE, errno, "can't make a pipe for DNS process");
  }
  fflush (stdout);
  pid = fork ();
  //pid = 1;
  if (pid < 0) {
    error(EXIT_FAILURE, errno, "can't fork for DNS process");
  }
  if (pid == 0) {
    char buf[2048];
    int i;
    FILE *infp; //, *outfp;

    // Automatically reap children. 
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
      error(EXIT_FAILURE, errno, "signal");
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

    while (fgets (buf, sizeof (buf), infp)) {
      ip_t host; 
      struct sockaddr_storage sa;
      socklen_t salen;
      char hostname [NI_MAXHOST];
      char result [INET6_ADDRSTRLEN + NI_MAXHOST + 2];

      if (!fork ()) {
        int rv;

        buf[strlen(buf)-1] = 0; // chomp newline.

        longipstr (buf, &host, ctl->af);
        //printf ("resolving %s (%d)\n", strlongip (ctl, &host), ctl->af);
        set_sockaddr_ip (ctl, &sa, &host);
        salen = (ctl->af == AF_INET)?sizeof(struct sockaddr_in):
                                sizeof(struct sockaddr_in6);

        rv = getnameinfo  ((struct sockaddr *) &sa, salen, 
			       hostname, sizeof (hostname), NULL, 0, 0);
        if (rv == 0) {
          sprintf (result, "%s %s\n", strlongip (ctl, &host), hostname);
          //printf ("resolved: %s -> %s (%d)\n", strlongip (ctl, &host), hostname, rv);
          rv = write (fromdns[1], result, strlen (result));
          if (rv < 0)
            error (0, errno, "write DNS lookup result");
        }

        exit(EXIT_SUCCESS);
      }
    }
    exit(EXIT_SUCCESS);
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

extern int dns_waitfd (void)
{
  return fromdns[0];
}


extern void dns_ack(struct mtr_ctl *ctl)
{
  char buf[2048], host[NI_MAXHOST], name[NI_MAXHOST];  
  ip_t hostip; 
  struct dns_results *r;

  while ( fgets (buf, sizeof (buf),  fromdnsfp )) {
    sscanf (buf, "%s %s", host, name);

    longipstr (host, &hostip, ctl->af);
    r = findip (ctl, &hostip);
    if (r)  
      r->name = strdup (name);
    else 
      error (0, 0, "dns_ack: Couldn't find host %s", host);
  }
}



#ifdef ENABLE_IPV6

extern int dns_waitfd6 (void)
{
  return  -1;
}

extern void dns_ack6(void)
{
  return;
}

#endif


extern char *dns_lookup2(struct mtr_ctl *ctl, ip_t * ip)
{
  struct dns_results *r;
  char buf[INET6_ADDRSTRLEN + 1];
  int rv;
   
  r = findip (ctl, ip);
  if (r) {
     // we've got a result. 
     if (r->name) 
        return r->name;
     else
        return strlongip (ctl, ip);
  } else {
     r = xmalloc (sizeof (struct dns_results));
     //r->ip = *ip;
     memcpy (&r->ip, ip, sizeof (r->ip));
     r->name = NULL;
     r->next = results;
     results = r;

     //printf ("lookup: %s\n", strlongip (ctl, ip));

     sprintf (buf, "%s\n", strlongip (ctl, ip));
     rv = write  (todns[1], buf, strlen (buf));
     if (rv < 0)
       error (0, errno, "couldn't write to resolver process");
  }
  return strlongip (ctl, ip);
}


extern char *dns_lookup(struct mtr_ctl *ctl, ip_t * ip)
{
  char *t;

  if (!ctl->dns)
    return NULL;
  t = dns_lookup2(ctl, ip);
  return t;
}


#if 0
extern char *strlongip(struct mtr_ctl *ctl, ip_t * ip)
{
#ifdef ENABLE_IPV6
  static char addrstr[INET6_ADDRSTRLEN];

  return (char *) inet_ntop( ctl->af, ip, addrstr, sizeof addrstr );
#else
  return inet_ntoa( *ip );
#endif
}
#endif


// XXX check if necessary/exported. 

/* Resolve an IP address to a hostname. */ 
extern struct hostent *addr2host( const char *addr, int family ) {
  int len = 0;
  switch ( family ) {
  case AF_INET:
    len = sizeof( struct in_addr );
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    len = sizeof( struct in6_addr );
    break;
#endif
  }
  return gethostbyaddr( addr, len, family );
}



