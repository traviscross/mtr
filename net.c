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
#include <stdlib.h>
#include <math.h>
#include <errno.h>

#include "net.h"
#include "display.h"


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
  uint32 addrs[MAXPATH];	/* for multi paths byMin */
  int xmit;
  int returned;
  int sent;
  int up;
  long long var;/* variance, could be overflowed */
  int last;
  int best;
  int worst;
  int avg;	/* average:  addByMin */
  int gmean;	/* geometirc mean: addByMin */
  int jitter;	/* current jitter, defined as t1-t0 addByMin */
//int jbest;	/* min jitter, of cause it is 0, not needed */
  int javg;	/* avg jitter */
  int jworst;	/* max jitter */
  int jinta;	/* estimated variance,? rfc1889's "Interarrival Jitter" */
  int transit;
  int saved[SAVED_PINGS];
  int saved_seq_offset;
};


struct sequence {
  int index;
  int transit;
  int saved_seq;
  struct timeval time;
};


/* Configuration parameter: How many queries to unknown hosts do we
   send? (This limits the amount of traffic generated if a host is not
   reachable) -- REW */
#define MAX_UNKNOWN_HOSTS 5


/* There is something stupid with BSD. We now detect this automatically */
static int BSDfix = 0;
#define saddr_correction(addr) BSDfix ? addr : 0

static struct nethost host[MaxHost];
static struct sequence sequence[MaxSequence];
static struct timeval reset = { 0, 0 };

int    timestamp;
int    sendsock;
int    recvsock;
struct sockaddr_in sourceaddress;
struct sockaddr_in remoteaddress;

/* XXX How do I code this to be IPV6 compatible??? -- REW */
struct in_addr localaddr;

static int batch_at = 0;
static int numhosts = 10;

extern int fstTTL;		/* initial hub(ttl) to ping byMin */
extern int maxTTL;		/* last hub to ping byMin*/
extern int packetsize;		/* packet size used by ping */
extern int bitpattern;		/* packet bit pattern used by ping */
extern int tos;			/* type of service set in ping packet*/



/* return the number of microseconds to wait before sending the next
   ping */
int calc_deltatime (float waittime)
{
  waittime /= numhosts;
  return 1000000 * waittime;
}


/* This doesn't work for odd sz. I don't know enough about this to say
   that this is wrong. It doesn't seem to cripple mtr though. -- REW */
int checksum(void *data, int sz) 
{
  unsigned short *ch;
  unsigned int sum;

  sum = 0;
  ch = data;
  sz = sz / 2;
  while (sz--) {
    sum += *(ch++);
  }
  
  sum = (sum >> 16) + (sum & 0xffff);  

  return (~sum & 0xffff);  
}


int new_sequence(int index) 
{
  static int next_sequence = 0;
  int seq;

  seq = next_sequence++;
  if (next_sequence >= MaxSequence)
    next_sequence = 0;

  sequence[seq].index = index;
  sequence[seq].transit = 1;
  sequence[seq].saved_seq = ++host[index].xmit;
  memset(&sequence[seq].time, 0, sizeof(sequence[seq].time));
  
  host[index].transit = 1;
  if (host[index].sent)
    host[index].up = 0;
  host[index].sent = 1;
  net_save_xmit(index);
  
  return seq;
}


/*  Attempt to find the host at a particular number of hops away  */
void net_send_query(int index) 
{
  /*ok  char packet[sizeof(struct IPHeader) + sizeof(struct ICMPHeader)];*/
  char packet[MAXPACKET];
  struct IPHeader *ip;
  struct ICMPHeader *icmp;

  /*ok  int packetsize = sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + datasize;*/
  int rv;
  static int first=1;

  if ( packetsize < MINPACKET ) packetsize = MINPACKET;
  if ( packetsize > MAXPACKET ) packetsize = MAXPACKET;

  memset(packet, (unsigned char) abs(bitpattern), abs(packetsize));

  ip = (struct IPHeader *)packet;
  icmp = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));

  ip->version = 0x45;
  ip->tos = tos;
  ip->len = BSDfix ? abs(packetsize): htons (abs(packetsize));
  ip->id = 0;
  ip->frag = 0;    /* 1, if want to find mtu size? Min */
  ip->ttl = index + 1;
  ip->protocol = IPPROTO_ICMP;
  ip->check = 0;

  /* BSD needs the source address here, Linux & others do not... */
  ip->saddr = saddr_correction(sourceaddress.sin_addr.s_addr);
  ip->daddr = remoteaddress.sin_addr.s_addr;

  icmp->type     = ICMP_ECHO;
  icmp->code     = 0;
  icmp->checksum = 0;
  icmp->id       = getpid();
  icmp->sequence = new_sequence(index);

  icmp->checksum = checksum(icmp, abs(packetsize) - sizeof(struct IPHeader));
  ip->check = checksum(ip, abs(packetsize));

  gettimeofday(&sequence[icmp->sequence].time, NULL);
  rv = sendto(sendsock, packet, abs(packetsize), 0, 
	      (struct sockaddr *)&remoteaddress, sizeof(remoteaddress));
  if (first && (rv < 0) && (errno == EINVAL)) {
    ip->len = abs (packetsize);
    rv = sendto(sendsock, packet, abs(packetsize), 0, 
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
void net_process_ping(int seq, uint32 addr, struct timeval now) 
{
  int index;
  int totusec;
  int oldavg;	/* usedByMin */
  int oldjavg;	/* usedByMin */
  int i;	/* usedByMin */

  if (seq < 0 || seq >= MaxSequence)
    return;

  if (!sequence[seq].transit)
    return;
  sequence[seq].transit = 0;

  index = sequence[seq].index;

  totusec = (now.tv_sec  - sequence[seq].time.tv_sec ) * 1000000 +
            (now.tv_usec - sequence[seq].time.tv_usec);
  /* impossible? if( totusec < 0 ) totusec = 0 */;

  if (host[index].addr == 0) {
    host[index].addr = addr;	// should be out of if as addr can change
    display_rawhost(index, host[index].addr);

  /* multi paths by Min */
    host[index].addrs[0] = addr;
  } else {
    for( i=0; i<MAXPATH; ) {
      if( host[index].addrs[i] == addr || host[index].addrs[i] == 0 ) break;
      i++;
    }
    if( host[index].addrs[i] != addr && i<MAXPATH ) {
      host[index].addrs[i] = addr;
    }
  /* end multi paths */
  }

  host[index].jitter = totusec - host[index].last;
  if (host[index].jitter < 0 ) host[index].jitter = - host[index].jitter;
  host[index].last = totusec;

  if (host[index].returned < 1) {
    host[index].best = host[index].worst = host[index].gmean = totusec;
    host[index].avg  = host[index].var  = 0;

    host[index].jitter = host[index].jworst = host[index].jinta= 0;
  }

  /* some time best can be too good to be true, experienced 
   * at least in linux 2.4.x.
   *  safe guard 1) best[index]>=best[index-1] if index>0
   *             2) best >= average-20,000 usec (good number?)
   *  Min
  if (index > 0) {
    if (totusec < host[index].best &&
       totusec>= host[index-1].best) host[index].best  = totusec;
  } else {
    if(totusec < host[index].best) host[index].best  = totusec;
  }
   */
  if (totusec < host[index].best ) host[index].best  = totusec;
  if (totusec > host[index].worst) host[index].worst = totusec;

  if (host[index].jitter > host[index].jworst)
	host[index].jworst = host[index].jitter;

  host[index].returned++;
  /* begin addByMin do more stats */
  oldavg = host[index].avg;
  host[index].avg += (totusec - oldavg +.0) / host[index].returned;
  host[index].var += (totusec - oldavg +.0) * (totusec - host[index].avg);

  oldjavg = host[index].javg;
  host[index].javg += (host[index].jitter - oldjavg) / host[index].returned;
  /* below algorithm is from rfc1889, A.8 */
  host[index].jinta += host[index].jitter - ((host[index].jinta + 8) >> 4);

  if ( host[index].returned > 1 )
  host[index].gmean = pow( (double) host[index].gmean, (host[index].returned-1.0)/host[index].returned )
			* pow( (double) totusec, 1.0/host[index].returned );
  /* end addByMin*/
  host[index].sent = 0;
  host[index].up = 1;
  host[index].transit = 0;

  net_save_return(index, sequence[seq].saved_seq, totusec);
  display_rawping(index, totusec);
}


/*  We know a packet has come in, because the main select loop has called us,
    now we just need to read it, see if it is for us, and if it is a reply 
    to something we sent, then call net_process_ping()  */
void net_process_return() 
{
  char packet[MAXPACKET];
  struct sockaddr_in fromaddr;
  int fromaddrsize;
  int num;
  struct ICMPHeader *header;
  struct timeval now;

  gettimeofday(&now, NULL);

  fromaddrsize = sizeof(fromaddr);
  num = recvfrom(recvsock, packet, MAXPACKET, 0, 
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


int net_addrs(int at, int i) {
  return ntohl(host[at].addrs[i]);
}



int net_loss(int at) 
{
  if ((host[at].xmit - host[at].transit) == 0) 
    return 0;
  /* times extra 1000 */
  return 1000*(100 - (100.0 * host[at].returned / (host[at].xmit - host[at].transit)) );
}


int net_drop(int at) 
{
  return (host[at].xmit - host[at].transit) - host[at].returned;
}


int net_last(int at) 
{
  return (host[at].last);
}


int net_best(int at) 
{
  return (host[at].best);
}


int net_worst(int at) 
{
  return (host[at].worst);
}


int net_avg(int at) 
{
  return (host[at].avg);
}


int net_gmean(int at) 
{
  return (host[at].gmean);
}


int net_stdev(int at) 
{
  if( host[at].returned > 1 ) {
    return ( sqrt( host[at].var/(host[at].returned -1.0) ) );
  } else {
    return( 0 );
  }
}


/* jitter stuff */
int net_jitter(int at) 
{ 
  return (host[at].jitter); 
}


int net_jworst(int at) 
{ 
  return (host[at].jworst); 
}


int net_javg(int at) 
{ 
  return (host[at].javg); 
}


int net_jinta(int at) 
{ 
  return (host[at].jinta); 
}
/* end jitter */


int net_max() 
{
  int at;
  int max;

  max = 0;
  // replacedByMin
  // for(at = 0; at < MaxHost-2; at++) {
  for(at = 0; at < maxTTL-1; at++) {
    if(host[at].addr == remoteaddress.sin_addr.s_addr) {
      return at + 1;
    } else if(host[at].addr != 0) {
      max = at + 2;
    }
  }

  return max;
}


/* add by Min (wonder its named net_min;-)) because of ttl stuff */
int net_min () 
{
  return ( fstTTL - 1 );
}


/* Added by Brian Casey December 1997 bcasey@imagiware.com*/
int net_returned(int at) 
{ 
  return host[at].returned;
}


int net_xmit(int at) 
{ 
  return host[at].xmit;
}


int net_transit(int at) 
{ 
  return host[at].transit;
}


int net_up(int at) 
{
   return host[at].up;
}


struct in_addr *net_localaddr (void)
{
  return &localaddr;
}


void net_end_transit() 
{
  int at;
  
  for(at = 0; at < MaxHost; at++) {
    host[at].transit = 0;
  }
}

int net_send_batch() 
{
  int n_unknown=0, i;

  /* randomized packet size and/or bit pattern if packetsize<0 and/or 
     bitpattern<0.  abs(packetsize) and/or abs(bitpattern) will be used 
  */
  if( batch_at < fstTTL ) {
    if( packetsize < 0 ) {
      packetsize = 
	- (int)(MINPACKET + (MAXPACKET-MINPACKET)*(rand()/(RAND_MAX+0.1)));
    }
    if( bitpattern < 0 ) {
      bitpattern = - (int)(256 + 255*(rand()/(RAND_MAX+0.1)));
    }
  }

  net_send_query(batch_at);

  for (i=fstTTL-1;i<batch_at;i++) {
    if (host[i].addr == 0)
      n_unknown++;

    /* The second condition in the next "if" statement was added in mtr-0.56, 
	but I don't remember why. It makes mtr stop skipping sections of unknown
	hosts. Removed in 0.65. 
	If the line proves neccesary, it should at least NOT trigger that line 
	when host[i].addr == 0 -- REW */
    if ((host[i].addr == remoteaddress.sin_addr.s_addr) 
	/* || (host[i].addr == host[batch_at].addr)  */)
      n_unknown = MaxHost; /* Make sure we drop into "we should restart" */
  }

  if (	// success in reaching target
      (host[batch_at].addr == remoteaddress.sin_addr.s_addr) ||
      // fail in consecuitive MAX_UNKNOWN_HOSTS (firewall?)
      (n_unknown > MAX_UNKNOWN_HOSTS) ||
      // or reach limit 
      (batch_at >= maxTTL-1)) {
    numhosts = batch_at+1;
    batch_at = fstTTL - 1;
    return 1;
  }

  batch_at++;
  return 0;
}


int net_preopen() 
{
  int trueopt = 1;

  sendsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sendsock < 0)
    return -1;

#ifdef IP_HDRINCL
  /*  FreeBSD wants this to avoid sending out packets with protocol type RAW
      to the network.  */
  if (setsockopt(sendsock, SOL_IP, IP_HDRINCL, &trueopt, sizeof(trueopt))) {
    perror("setsockopt(IP_HDRINCL,1)");
    return -1;
  }
#endif

  recvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (recvsock < 0)
    return -1;

  return 0;
}

 
int net_open(int addr) 
{
  struct sockaddr_in name; 
  int len; 

  net_reset();

  remoteaddress.sin_family = AF_INET;
  remoteaddress.sin_addr.s_addr = addr;

  len = sizeof (name); 
  getsockname (recvsock, (struct sockaddr *)&name, &len);
  localaddr = name.sin_addr;
#if 0
  printf ("got localaddr: %x\n", *(int *)&localaddr); 
#endif

  return 0;
}


void net_reopen(int addr) 
{
  int at;

  for(at = 0; at < MaxHost; at++) {
    memset(&host[at], 0, sizeof(host[at]));
  }

  remoteaddress.sin_family = AF_INET;
  remoteaddress.sin_addr.s_addr = addr;

  net_reset ();
  net_send_batch();
}


void net_reset() 
{
  int at;
  int i;

  batch_at = fstTTL - 1;	/* above replacedByMin */
  numhosts = 10;

  for (at = 0; at < MaxHost; at++) {
    host[at].xmit = 0;
    host[at].transit = 0;
    host[at].returned = 0;
    host[at].sent = 0;
    host[at].up = 0;
    host[at].last = 0;
    host[at].avg  = 0;
    host[at].best = 0;
    host[at].worst = 0;
    host[at].gmean = 0;
    host[at].var = 0;
    host[at].jitter = 0;
    host[at].javg = 0;
    host[at].jworst = 0;
    host[at].jinta = 0;
    for (i=0; i<SAVED_PINGS; i++) {
      host[at].saved[i] = -2;	/* unsent */
    }
    host[at].saved_seq_offset = -SAVED_PINGS+2;
  }
  
  for (at = 0; at < MaxSequence; at++) {
    sequence[at].transit = 0;
  }

  gettimeofday(&reset, NULL);
}


int net_set_interfaceaddress (char *InterfaceAddress)
{
  int i1, i2, i3, i4;
  char dummy;

  if (!InterfaceAddress) return 0; 

  sourceaddress.sin_family = AF_INET;
  sourceaddress.sin_port = 0;
  sourceaddress.sin_addr.s_addr = 0;

  if(sscanf(InterfaceAddress, "%u.%u.%u.%u%c", &i1, &i2, &i3, &i4, &dummy) != 4) {
    printf("mtr: bad interface address: %s\n", InterfaceAddress);
    exit(1);
  }

  ((unsigned char*)&sourceaddress.sin_addr)[0] = i1;
  ((unsigned char*)&sourceaddress.sin_addr)[1] = i2;
  ((unsigned char*)&sourceaddress.sin_addr)[2] = i3;
  ((unsigned char*)&sourceaddress.sin_addr)[3] = i4;

  if(bind(sendsock, (struct sockaddr*)&sourceaddress, sizeof(sourceaddress)) == -1) {
    perror("mtr: failed to bind to interface");
    exit(1);
  }
  return 0; 
}



void net_close() 
{
  close(sendsock);
  close(recvsock);
}


int net_waitfd() 
{
  return recvsock;
}


int* net_saved_pings(int at) 
{
  return host[at].saved;
}


void net_save_increment() 
{
  int at;
  for (at = 0; at < MaxHost; at++) {
    memmove(host[at].saved, host[at].saved+1, (SAVED_PINGS-1)*sizeof(int));
    host[at].saved[SAVED_PINGS-1] = -2;
    host[at].saved_seq_offset += 1;
  }
}


void net_save_xmit(int at) 
{
  if (host[at].saved[SAVED_PINGS-1] != -2) 
    net_save_increment();
  host[at].saved[SAVED_PINGS-1] = -1;
}


void net_save_return(int at, int seq, int ms) 
{
  int idx;
  idx = seq - host[at].saved_seq_offset;
  if (idx < 0 || idx > SAVED_PINGS) {
    return;
  }
  host[at].saved[idx] = ms;
}
