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

#if defined(HAVE_SYS_XTI_H)
#include <sys/xti.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <memory.h>
#include <unistd.h>

#include "net.h"

#define MaxHost 256
#define MaxTransit 4

/*  We can't rely on header files to provide this information, because
    the fields have different names between, for instance, Linux and 
    Solaris  */
struct ICMPHeader {
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short id;
  unsigned short sequence;
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
#define ICMP_TIME_EXCEEDED	11
  
#ifndef SOL_IP
#define SOL_IP 0
#endif
  
struct packetdata {
    int index;
    int ttl;
    int sec;
    int msec;
};

struct nethost {
  int addr;
  int xmit;
  int returned;
  int total;
  int best;
  int worst;
  int transit;
};

static struct nethost host[MaxHost];
static struct timeval reset = { 0, 0 };

int sendsock;
int recvsock;
struct sockaddr_in remoteaddress;

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

void net_send_ping(int index) {
  char packet[sizeof(struct IPHeader) + sizeof(struct ICMPHeader) 
	     + sizeof(struct packetdata)];
  struct IPHeader *ip;
  struct ICMPHeader *icmp;
  struct packetdata *data;
  int packetsize = sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + sizeof(struct packetdata);
  struct sockaddr_in addr;
  struct timeval now;

  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = host[index].addr;
  host[index].xmit++;
  host[index].transit = 1;

  memset(packet, 0, packetsize);

  ip = (struct IPHeader *)packet;
  icmp = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));
  data = (struct packetdata *)(packet + sizeof(struct IPHeader) + sizeof(struct ICMPHeader));

  ip->version = 0x45;
  ip->tos = 0;
  ip->len = packetsize;
  ip->id = 0;
  ip->frag = 0;
  ip->ttl = 127;
  ip->protocol = IPPROTO_ICMP;
  ip->saddr = 0;
  ip->daddr = host[index].addr;
  
  icmp->type = ICMP_ECHO;
  icmp->id = getpid();
  icmp->sequence = 0;

  data->ttl = 0;
  data->index = index;

  gettimeofday(&now, NULL);
  data->sec = now.tv_sec;
  data->msec = now.tv_usec / 1000;

  icmp->checksum = checksum(icmp, packetsize - sizeof(struct IPHeader));
  ip->check = checksum(ip, packetsize);

  sendto(sendsock, packet, packetsize, 0, 
	 (struct sockaddr *)&addr, sizeof(addr));
}

/*  Attempt to find the host at a particular number of hops away  */
void net_send_query(int hops) {
  char packet[sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + sizeof(struct packetdata)];
  struct IPHeader *ip;
  struct ICMPHeader *icmp;
  struct packetdata *data;
  int packetsize = sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + sizeof(struct packetdata);

  memset(packet, 0, packetsize);

  ip = (struct IPHeader *)packet;
  icmp = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));
  data = (struct packetdata *)(packet + sizeof(struct IPHeader) + sizeof(struct ICMPHeader));

  ip->version = 0x45;
  ip->tos = 0;
  ip->len = packetsize;
  ip->id = 0;
  ip->frag = 0;
  ip->ttl = hops;
  ip->protocol = IPPROTO_ICMP;
  ip->saddr = 0;
  ip->daddr = remoteaddress.sin_addr.s_addr;

  icmp->type = ICMP_ECHO;
  icmp->id = getpid();
  icmp->sequence = hops;

  data->ttl = hops;
  data->index = -1;

  icmp->checksum = checksum(icmp, packetsize - sizeof(struct IPHeader));
  ip->check = checksum(ip, packetsize);

  sendto(sendsock, packet, packetsize, 0, 
	 (struct sockaddr *)&remoteaddress, sizeof(remoteaddress));
}

void net_process_ping(struct packetdata *data, struct sockaddr_in *addr) {
  int at;
  struct timeval now;
  int totmsec;
  int msec;

  if(data->index >= 0) {
    gettimeofday(&now, NULL);

    if(data->sec < reset.tv_sec
       || (data->sec == reset.tv_sec && (1000*data->msec) < reset.tv_usec))
      /* discard this data point, stats were reset after it was generated */
      return;
    
    totmsec = (now.tv_sec - data->sec) * 1000;
    msec = now.tv_usec / 1000 - data->msec;
    if(msec >= 0) 
      totmsec += msec;
    else
      totmsec = totmsec - 1000 + 1000 - data->msec + now.tv_usec / 1000;

    if(host[data->index].returned <= 0) {
      host[data->index].best = host[data->index].worst = totmsec;
    }

    if(totmsec < host[data->index].best)
      host[data->index].best = totmsec;

    if(totmsec > host[data->index].worst)
      host[data->index].worst = totmsec;

    host[data->index].total += totmsec;
    host[data->index].returned++;
    host[data->index].transit = 0;
  } else {
    at = data->ttl - 1;
    if(at < 0 || at > MaxHost)
      return;

    host[at].addr = addr->sin_addr.s_addr;
  }
}

void net_process_return() {
  char packet[2048];
  struct sockaddr_in fromaddr;
  int fromaddrsize;
  int num;
  int at;
  struct ICMPHeader *header;

  fromaddrsize = sizeof(fromaddr);
  num = recvfrom(recvsock, packet, 2048, 0, 
		 (struct sockaddr *)&fromaddr, &fromaddrsize);

  if(num < sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + sizeof(struct packetdata))
    return;

  header = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));
  if(header->type == ICMP_ECHOREPLY) {
    if(header->id != getpid())
      return;

    net_process_ping((struct packetdata *)(packet + sizeof(struct IPHeader) + 
					   sizeof(struct ICMPHeader)),
		     &fromaddr);
  } else if(header->type == ICMP_TIME_EXCEEDED) {
    if(num < sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + 
             sizeof(struct IPHeader) + sizeof(struct ICMPHeader))
      return;
    
    header = (struct ICMPHeader *)(packet + sizeof(struct IPHeader) + 
				sizeof(struct ICMPHeader) + sizeof(struct IPHeader));
    if(header->id != getpid())
      return;
    
    at = header->sequence - 1;
    if(at < 0 || at > MaxHost)
      return;

    host[at].addr = fromaddr.sin_addr.s_addr;
  }
}

int net_addr(int at) {
  return ntohl(host[at].addr);
}

int net_percent(int at) {
  if(host[at].xmit == 0) 
    return 0;

  return 100 - (100 * (host[at].returned + host[at].transit) / host[at].xmit);
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
  for(at = 0; at < MaxHost; at++) {
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


extern float WaitTime;
extern struct timeval intervaltime;
#include <stdio.h>
#include <math.h>

int net_send_batch() {
  static int n_unknown = 10;
  static int at;

  if(host[at].addr == 0) {
    net_send_query(at + 1);
    n_unknown--;
  } else {
    net_send_ping(at);
  }
  
  if ((host[at].addr == remoteaddress.sin_addr.s_addr) ||
      (n_unknown == 0)) {
    float wt = WaitTime / (float) at;

    intervaltime.tv_sec = (int)(wt);
    intervaltime.tv_usec = 1000000.0 * (wt - floor(wt));
    at = 0;
    n_unknown = 10;
    return 1;
  }

  at++;
  return 0;
}


int net_preopen() {
  int trueopt = 1;

  sendsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if(sendsock == -1)
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
  if(recvsock == -1)
    return -1;  

  return 0;
}
 
int net_open(int addr) {
  remoteaddress.sin_family = AF_INET;
  remoteaddress.sin_addr.s_addr = addr;

  net_send_batch();

  return 0;
}

void net_reopen(int addr) {
  int at;

  for(at = 0; at < MaxHost; at++) {
    memset(&host[at], 0, sizeof(host[at]));
  }

  remoteaddress.sin_family = AF_INET;
  remoteaddress.sin_addr.s_addr = addr;

  net_send_batch();
}

void net_reset() {
  int at;

  for(at = 0; at < MaxHost; at++) {
    host[at].xmit = host[at].transit;
    host[at].returned = 0;
    host[at].total = 0;
    host[at].best = 0;
    host[at].worst = 0;
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


