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
    
   1999-08-13 ok Olav@okvittem.priv.no  added -psize

*/

#include <config.h>

#if defined(HAVE_SYS_XTI_H)
#include <sys/xti.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <memory.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>

#include "net.h"



#define MaxTransit 4

/*  We can't rely on header files to provide this information, because
    the fields have different names between, for instance, Linux and 
    Solaris  */
struct ICMPHeader {
  uint8 type;
  uint8 code;
  uint16 checksum;
  uint16 id;
  uint16 sequence;
};

/*  Structure of an IP header.  */
struct IPHeader {
  uint8 version;
  uint8 tos;
  uint16 len;
  uint16 id;
  uint16 frag;
  uint8 ttl;
  uint8 protocol;
  uint16 check;
  uint32 saddr;
  uint32 daddr;
};
  
#define ICMP_ECHO		8
#define ICMP_ECHOREPLY		0

#define ICMP_TSTAMP		13
#define ICMP_TSTAMPREPLY	14

#define ICMP_TIME_EXCEEDED	11

#ifndef SOL_IP
#define SOL_IP 0
#endif



struct nethost {
  uint32 addr;
  int xmit;
  int returned;
  long long total;
  int last;
  int best;
  int worst;
  int transit;
  int saved[SAVED_PINGS];
};

struct sequence {
    int index;
    int transit;
    int saved_seq;
    struct timeval time;
};


/* Configuration parameter: How many queries to unknown hosts do we
   send? (This limits the amount of traffic generated if a host is not
   reachable) */
#define MAX_UNKNOWN_HOSTS 5


static struct nethost host[MaxHost];
static struct sequence sequence[MaxSequence];
static struct timeval reset = { 0, 0 };

int timestamp;
int sendsock;
int recvsock;
struct sockaddr_in remoteaddress;
static int batch_at = 0;


extern int packetsize;
static int numhosts = 10;

/* return the number of microseconds to wait before sending the next
   ping */
int calc_deltatime (float waittime)
{
  waittime /= numhosts;
  return 1000000 * waittime;
}


/* This doesn't work for odd sz. I don't know enough about this to say
   that this is wrong. It doesn't seem to cripple mtr though. -- REW */
int checksum(void *data, int sz) {
  unsigned short *ch;
  unsigned int sum;

  sum = 0;
  ch = data;
  sz = sz / 2;
  while(sz--) {
    sum += *(ch++);
  }
  
  sum = (sum >> 16) + (sum & 0xffff);  

  return (~sum & 0xffff);  
}


static int BSDfix = 0;

int new_sequence(int index) {
  static int next_sequence = 0;
  int seq;

  seq = next_sequence++;
  if(next_sequence >= MaxSequence)
    next_sequence = 0;

  sequence[seq].index = index;
  sequence[seq].transit = 1;
  sequence[seq].saved_seq = ++host[index].xmit;
  memset(&sequence[seq].time, 0, sizeof(sequence[seq].time));
  
  host[index].transit = 1;
  net_save_xmit(index);
  
  return seq;
}

/*  Attempt to find the host at a particular number of hops away  */
void net_send_query(int index) {
  /*ok  char packet[sizeof(struct IPHeader) + sizeof(struct ICMPHeader)];*/
  char packet[MAXPACKET];
  struct IPHeader *ip;
  struct ICMPHeader *icmp;

  /*ok  int packetsize = sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + datasize;*/
  int rv;
  static int first=1;

  if ( packetsize < MINPACKET ) packetsize = MINPACKET;
  if ( packetsize > MAXPACKET ) packetsize = MAXPACKET;
  memset(packet, 0, packetsize);

  ip = (struct IPHeader *)packet;
  icmp = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));

  ip->version = 0x45;
  ip->tos = 0;
  ip->len = BSDfix ? packetsize: htons (packetsize);
  ip->id = 0;
  ip->frag = 0;
  ip->ttl = index + 1;
  ip->protocol = IPPROTO_ICMP;
  ip->saddr = 0;
  ip->daddr = remoteaddress.sin_addr.s_addr;

  icmp->type = ICMP_ECHO;
  icmp->id = getpid();
  icmp->sequence = new_sequence(index);

  icmp->checksum = checksum(icmp, packetsize - sizeof(struct IPHeader));
  ip->check = checksum(ip, packetsize);

  gettimeofday(&sequence[icmp->sequence].time, NULL);
  rv = sendto(sendsock, packet, packetsize, 0, 
	 (struct sockaddr *)&remoteaddress, sizeof(remoteaddress));
  if (first && (rv < 0) && (errno == EINVAL)) {
    ip->len = packetsize;
    rv = sendto(sendsock, packet, packetsize, 0, 
		(struct sockaddr *)&remoteaddress, sizeof(remoteaddress));
    if (rv >= 0) {
      fprintf (stderr, "You've got a broken (FreeBSD?) system\n");
      BSDfix = 1;
    }
  }
  first = 0;
}

/*   We got a return on something we sent out.  Record the address and
     time.  */
void net_process_ping(int seq, uint32 addr, struct timeval now) {
  int index;
  int totusec;

  if(seq < 0 || seq >= MaxSequence)
    return;

  if(!sequence[seq].transit)
    return;
  sequence[seq].transit = 0;

  index = sequence[seq].index;

  totusec = (now.tv_sec  - sequence[seq].time.tv_sec ) * 1000000 +
            (now.tv_usec - sequence[seq].time.tv_usec);

  if(host[index].addr == 0) {
    host[index].addr = addr;
    display_rawhost(index, host[index].addr);
  }
  if(host[index].returned <= 0) {
    host[index].best = host[index].worst = totusec;
  }
  host[index].last = totusec;
  if(totusec < host[index].best)
    host[index].best = totusec;
  if(totusec > host[index].worst)
    host[index].worst = totusec;

  host[index].total += totusec;
  host[index].returned++;
  host[index].transit = 0;

  net_save_return(index, sequence[seq].saved_seq, totusec);
  display_rawping(index, totusec);
}

/*  We know a packet has come in, because the main select loop has called us,
    now we just need to read it, see if it is for us, and if it is a reply 
    to something we sent, then call net_process_ping()  */
void net_process_return() {
  char packet[2048];
  struct sockaddr_in fromaddr;
  int fromaddrsize;
  int num;
  int at;
  struct ICMPHeader *header;
  struct timeval now;

  gettimeofday(&now, NULL);

  fromaddrsize = sizeof(fromaddr);
  num = recvfrom(recvsock, packet, 2048, 0, 
		 (struct sockaddr *)&fromaddr, &fromaddrsize);

  if(num < sizeof(struct IPHeader) + sizeof(struct ICMPHeader))
    return;

  header = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));
  if(header->type == ICMP_ECHOREPLY) {
    if(header->id != (uint16)getpid())
      return;

    net_process_ping(header->sequence, fromaddr.sin_addr.s_addr, now);
  } else if(header->type == ICMP_TIME_EXCEEDED) {
    if(num < sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + 
             sizeof(struct IPHeader) + sizeof(struct ICMPHeader))
      return;
    
    header = (struct ICMPHeader *)(packet + sizeof(struct IPHeader) + 
				sizeof(struct ICMPHeader) + sizeof(struct IPHeader));
    if(header->id != (uint16)getpid())
      return;

    net_process_ping(header->sequence, fromaddr.sin_addr.s_addr, now);
  }
}

int net_addr(int at) {
  return ntohl(host[at].addr);
}

int net_percent(int at) {
  if((host[at].xmit - host[at].transit) == 0) 
    return 0;

  return 100 - (100 * host[at].returned / (host[at].xmit - host[at].transit));
}

int net_last(int at) {
  return host[at].last;
}

int net_best(int at) {
  return host[at].best;
}

int net_worst(int at) {
  return host[at].worst;
}

int net_avg(int at) {
  if(host[at].returned == 0)
    return 0;

  return host[at].total / host[at].returned;
}

int net_max() {
  int at;
  int max;

  max = 0;
  for(at = 0; at < MaxHost-2; at++) {
    if(host[at].addr == remoteaddress.sin_addr.s_addr) {
      return at + 1;
    } else if(host[at].addr != 0) {
      max = at + 2;
    }
  }

  return max;
}


/* Added by Brian Casey December 1997 bcasey@imagiware.com*/
int net_returned(int at) { 
   return host[at].returned;
}
int net_xmit(int at) { 
   return host[at].xmit;
}
int net_transit(int at) { 
   return host[at].transit;
}

void net_end_transit() {
  int at;

  for(at = 0; at < MaxHost; at++) {
    host[at].transit = 0;
  }
}



int net_send_batch() {
  int n_unknown, i;

  net_send_query(batch_at);

  n_unknown = 0;

  for (i=0;i<batch_at;i++) {
    if (host[i].addr == 0)
      n_unknown++;
    if (host[i].addr == remoteaddress.sin_addr.s_addr)
      n_unknown = 100; /* Make sure we drop into "we should restart" */
  }

  if ((host[batch_at].addr == remoteaddress.sin_addr.s_addr) ||
      (n_unknown > MAX_UNKNOWN_HOSTS) ||
      (batch_at >= MaxHost-2)) {
    numhosts = batch_at+1;
    batch_at = 0;
    return 1;
  }

  batch_at++;
  return 0;
}


int net_preopen() {
  int trueopt = 1;

  sendsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if(sendsock < 0)
    return -1;

#ifdef IP_HDRINCL
  /*  FreeBSD wants this to avoid sending out packets with protocol type RAW
      to the network.  */
  if(setsockopt(sendsock, SOL_IP, IP_HDRINCL, &trueopt, sizeof(trueopt)))
  {
    perror("setsockopt(IP_HDRINCL,1)");
    return -1;
  }
#endif

  recvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if(recvsock < 0)
    return -1;

  return 0;
}
 
int net_open(int addr) {
  net_reset();

  remoteaddress.sin_family = AF_INET;
  remoteaddress.sin_addr.s_addr = addr;

  return 0;
}

void net_reopen(int addr) {
  int at;

  for(at = 0; at < MaxHost; at++) {
    memset(&host[at], 0, sizeof(host[at]));
  }

  remoteaddress.sin_family = AF_INET;
  remoteaddress.sin_addr.s_addr = addr;

  net_reset ();
  net_send_batch();
}

void net_reset() {
  int at;
  int i;

  batch_at = 0;
  numhosts = 10;

  for(at = 0; at < MaxHost; at++) {
    host[at].xmit = 0;
    host[at].transit = 0;
    host[at].returned = 0;
    host[at].total = 0;
    host[at].best = 0;
    host[at].worst = 0;
    for (i=0; i<SAVED_PINGS; i++) {
      host[at].saved[i] = -2;	/* unsent */
    }
  }
  
  for(at = 0; at < MaxSequence; at++) {
    sequence[at].transit = 0;
  }

  gettimeofday(&reset, NULL);
}

void net_close() {
  close(sendsock);
  close(recvsock);
}

int net_waitfd() {
  return recvsock;
}


int* net_saved_pings(int at) {
	return host[at].saved;
}

void net_save_xmit(int at) {
	int tmp[SAVED_PINGS];
	memcpy(tmp, &host[at].saved[1], (SAVED_PINGS-1)*sizeof(int));
	memcpy(host[at].saved, tmp, (SAVED_PINGS-1)*sizeof(int));
	host[at].saved[SAVED_PINGS-1] = -1;
}

void net_save_return(int at, int seq, int ms) {
	int idx;
	idx = SAVED_PINGS - (host[at].xmit - seq) - 1;
	if (idx < 0) {
		return;
	}
	host[at].saved[idx] = ms;
}
