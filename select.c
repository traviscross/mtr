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
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#include "display.h"
#include "dns.h"
#include "net.h"

extern int Interactive;
extern int MaxPing;
extern float WaitTime;
double dnsinterval;

static struct timeval intervaltime;


void select_loop() {
  fd_set readfd;
  int anyset;
  int action, maxfd;
  int dnsfd, netfd;
  int NumPing;
  int paused;
  struct timeval lasttime, thistime, selecttime;
  float wt;
  int dt;
  int rv; 

  NumPing = 0; 
  anyset = 0;
  gettimeofday(&lasttime, NULL);
  paused=0;

  while(1) {
    dt = calc_deltatime (WaitTime);
    intervaltime.tv_sec  = dt / 1000000;
    intervaltime.tv_usec = dt % 1000000;

    FD_ZERO(&readfd);

    maxfd = 0;

    if(Interactive) {
      FD_SET(0, &readfd);
      maxfd = 1;
    }

    dnsfd = dns_waitfd();
    FD_SET(dnsfd, &readfd);
    if(dnsfd >= maxfd)
      maxfd = dnsfd + 1;

    netfd = net_waitfd();
    FD_SET(netfd, &readfd);
    if(netfd >= maxfd)
      maxfd = netfd + 1;

    do {
      if(anyset || paused) {
	selecttime.tv_sec = 0;
	selecttime.tv_usec = 0;
      
	rv = select(maxfd, (void *)&readfd, NULL, NULL, &selecttime);
      } else {
	if(Interactive) 
	  display_redraw();

	gettimeofday(&thistime, NULL);

	if(thistime.tv_sec > lasttime.tv_sec + intervaltime.tv_sec ||
	   (thistime.tv_sec == lasttime.tv_sec + intervaltime.tv_sec &&
	    thistime.tv_usec >= lasttime.tv_usec + intervaltime.tv_usec)) {
	  lasttime = thistime;
	  if(NumPing >= MaxPing && !Interactive)
	    return;
	  if (net_send_batch())
	    NumPing++;
	}

	selecttime.tv_usec = (thistime.tv_usec - lasttime.tv_usec);
	selecttime.tv_sec = (thistime.tv_sec - lasttime.tv_sec);
	if (selecttime.tv_usec < 0) {
	  --selecttime.tv_sec;
	  selecttime.tv_usec += 1000000;
	}
	selecttime.tv_usec = intervaltime.tv_usec - selecttime.tv_usec;
	selecttime.tv_sec = intervaltime.tv_sec - selecttime.tv_sec;
	if (selecttime.tv_usec < 0) {
	  --selecttime.tv_sec;
	  selecttime.tv_usec += 1000000;
	}

	if ((selecttime.tv_sec > (time_t)dnsinterval) ||
	    ((selecttime.tv_sec == (time_t)dnsinterval) &&
	     (selecttime.tv_usec > ((time_t)(dnsinterval * 1000000) % 1000000)))) {
	  selecttime.tv_sec = (time_t)dnsinterval;
	  selecttime.tv_usec = (time_t)(dnsinterval * 1000000) % 1000000;
	}

	rv = select(maxfd, (void *)&readfd, NULL, NULL, &selecttime);
      }
    } while ((rv < 0) && (errno == EINTR));

    if (rv < 0) {
      perror ("Select failed");
      exit (1);
    }
    anyset = 0;

    /* Handle any pending resolver events */
    dnsinterval = WaitTime;
    dns_events(&dnsinterval);

    /*  Has a key been pressed?  */
    if(FD_ISSET(0, &readfd)) {
      action = display_keyaction();

      if(action == ActionQuit)
	break;

      if(action == ActionReset) 
	net_reset();

      if (action == ActionDisplay) 
        display_mode = (display_mode+1) % 3;

      if (action == ActionClear) 
	display_clear();

      if (action == ActionPause) 
	paused=1;

      if (action == ActionResume) 
	paused=0;

      if (action == ActionDNS && dns) {
	use_dns = !use_dns;
	display_clear();
      }

      anyset = 1;
    }

    /*  Have we finished a nameservice lookup?  */
    if(FD_ISSET(dnsfd, &readfd)) {
      dns_ack();
      anyset = 1;
    }

    /*  Have we got new packets back?  */
    if(FD_ISSET(netfd, &readfd)) {
      net_process_return();
      anyset = 1;
    }
  }
}

