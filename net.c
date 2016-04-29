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

#if defined(HAVE_SYS_XTI_H)
#include <sys/xti.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <memory.h>
#include <unistd.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>

#include "mtr.h"
#include "net.h"
#include "display.h"
#include "dns.h"

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

/* Structure of an UDP header.  */
struct UDPHeader {
  uint16 srcport;
  uint16 dstport;
  uint16 length;
  uint16 checksum;
};

/* Structure of an TCP header, as far as we need it.  */
struct TCPHeader {
  uint16 srcport;
  uint16 dstport;
  uint32 seq;
};

/* Structure of an SCTP header */
struct SCTPHeader {
  uint16 srcport;
  uint16 dstport;
  uint32 veri_tag;
};

/* Structure of an IPv4 UDP pseudoheader.  */
struct UDPv4PHeader {
  uint32 saddr;
  uint32 daddr;
  uint8 zero;
  uint8 protocol;
  uint16 len;
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
#define ICMP_UNREACHABLE        3

#ifndef SOL_IP
#define SOL_IP 0
#endif

struct nethost {
  ip_t addr;
  ip_t addrs[MAXPATH];	/* for multi paths byMin */
  int xmit;
  int returned;
  int sent;
  int up;
  long long var;/* variance, could be overflowed */
  int last;
  int best;
  int worst;
  int avg;	/* average:  addByMin */
  int gmean;	/* geometric mean: addByMin */
  int jitter;	/* current jitter, defined as t1-t0 addByMin */
/*int jbest;*/	/* min jitter, of cause it is 0, not needed */
  int javg;	/* avg jitter */
  int jworst;	/* max jitter */
  int jinta;	/* estimated variance,? rfc1889's "Interarrival Jitter" */
  int transit;
  int saved[SAVED_PINGS];
  int saved_seq_offset;
  struct mplslen mpls;
  struct mplslen mplss[MAXPATH];
};


struct sequence {
  int index;
  int transit;
  int saved_seq;
  struct timeval time;
  int socket;
};


/* Configuration parameter: How many queries to unknown hosts do we
   send? (This limits the amount of traffic generated if a host is not
   reachable) */
#define MAX_UNKNOWN_HOSTS 5


/* BSD-derived kernels use host byte order for the IP length and 
   offset fields when using raw sockets.  We detect this automatically at 
   run-time and do the right thing. */
static int BSDfix = 0;

static struct nethost host[MaxHost];
static struct sequence sequence[MaxSequence];
static struct timeval reset = { 0, 0 };

int    timestamp;
int    sendsock4;
int    sendsock4_icmp;
int    sendsock4_udp;
int    recvsock4;
int    sendsock6;
int    sendsock6_icmp;
int    sendsock6_udp;
int    recvsock6;
int    sendsock;
int    recvsock;

#ifdef ENABLE_IPV6
struct sockaddr_storage sourcesockaddr_struct;
struct sockaddr_storage remotesockaddr_struct;
struct sockaddr_in6 * ssa6 = (struct sockaddr_in6 *) &sourcesockaddr_struct;
struct sockaddr_in6 * rsa6 = (struct sockaddr_in6 *) &remotesockaddr_struct;
#else
struct sockaddr_in sourcesockaddr_struct;
struct sockaddr_in remotesockaddr_struct;
#endif

struct sockaddr * sourcesockaddr = (struct sockaddr *) &sourcesockaddr_struct;
struct sockaddr * remotesockaddr = (struct sockaddr *) &remotesockaddr_struct;
struct sockaddr_in * ssa4 = (struct sockaddr_in *) &sourcesockaddr_struct;
struct sockaddr_in * rsa4 = (struct sockaddr_in *) &remotesockaddr_struct;

ip_t * sourceaddress;
ip_t * remoteaddress;

/* XXX How do I code this to be IPV6 compatible??? */
#ifdef ENABLE_IPV6
char localaddr[INET6_ADDRSTRLEN];
#else
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
char localaddr[INET_ADDRSTRLEN];
#endif

static int batch_at = 0;
static int numhosts = 10;

extern int fstTTL;		/* initial hub(ttl) to ping byMin */
extern int maxTTL;		/* last hub to ping byMin*/
extern int cpacketsize;		/* packet size used by ping */
static int packetsize;		/* packet size used by ping */
extern int bitpattern;		/* packet bit pattern used by ping */
extern int tos;			/* type of service set in ping packet*/
extern int af;			/* address family of remote target */
extern int mtrtype;		/* type of query packet used */
extern int remoteport;          /* target port for TCP tracing */
extern int localport;  /* source port for UDP tracing */
extern int tcp_timeout;             /* timeout for TCP connections */
#ifdef SO_MARK
extern int mark;		/* SO_MARK to set for ping packet*/
#endif

/* return the number of microseconds to wait before sending the next
   ping */
int calc_deltatime (float waittime)
{
  waittime /= numhosts;
  return 1000000 * waittime;
}


int checksum(void *data, int sz) 
{
  uint16 *ch;
  uint32 sum;
  uint16 odd;

  sum = 0;
  ch = data;
  if (sz % 2) {
    ((char *)&odd)[0] = ((char *)data)[sz - 1];
    sum = odd;
  }
  sz = sz / 2;
  while (sz--) {
    sum += *(ch++);
  }
  while (sum >> 16) {
    sum = (sum >> 16) + (sum & 0xffff);
  }

  return (~sum & 0xffff);  
}


/* Prepend pseudoheader to the udp datagram and calculate checksum */
int udp_checksum(void *pheader, void *udata, int psize, int dsize, int alt_checksum)
{
  unsigned int tsize = psize + dsize;
  char csumpacket[tsize];
  memset(csumpacket, (unsigned char) abs(bitpattern), abs(tsize));
  if (alt_checksum && dsize >= 2) {
    csumpacket[psize + sizeof(struct UDPHeader)] = 0;
    csumpacket[psize + sizeof(struct UDPHeader) + 1] = 0;
  }

  struct UDPv4PHeader *prepend = (struct UDPv4PHeader *) csumpacket;
  struct UDPv4PHeader *udppheader = (struct UDPv4PHeader *) pheader;
  prepend->saddr = udppheader->saddr;
  prepend->daddr = udppheader->daddr;
  prepend->zero = 0;
  prepend->protocol = udppheader->protocol;
  prepend->len = udppheader->len;

  struct UDPHeader *content = (struct UDPHeader *)(csumpacket + psize);
  struct UDPHeader *udpdata = (struct UDPHeader *) udata;
  content->srcport = udpdata->srcport;
  content->dstport = udpdata->dstport;
  content->length = udpdata->length;
  content->checksum = udpdata->checksum;

  return checksum(csumpacket,tsize);
}


void save_sequence(int index, int seq)
{
  display_rawxmit(index, seq);

  sequence[seq].index = index;
  sequence[seq].transit = 1;
  sequence[seq].saved_seq = ++host[index].xmit;
  memset(&sequence[seq].time, 0, sizeof(sequence[seq].time));
  
  host[index].transit = 1;
  if (host[index].sent)
    host[index].up = 0;
  host[index].sent = 1;
  net_save_xmit(index);
}

int new_sequence(int index)
{
  static int next_sequence = MinSequence;
  int seq;

  seq = next_sequence++;
  if (next_sequence >= MaxSequence)
    next_sequence = MinSequence;

  save_sequence(index, seq);

  return seq;
}

/*  Attempt to connect to a TCP port with a TTL */
void net_send_tcp(int index)
{
  int ttl, s;
  int opt = 1;
  int port;
  struct sockaddr_storage local;
  struct sockaddr_storage remote;
  struct sockaddr_in *local4 = (struct sockaddr_in *) &local;
  struct sockaddr_in6 *local6 = (struct sockaddr_in6 *) &local;
  struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
  struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
  socklen_t len;

  ttl = index + 1;

  s = socket(af, SOCK_STREAM, 0);
  if (s < 0) {
    display_clear();
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  memset(&local, 0, sizeof (local));
  memset(&remote, 0, sizeof (remote));
  local.ss_family = af;
  remote.ss_family = af;

  switch (af) {
  case AF_INET:
    addrcpy((void *) &local4->sin_addr, (void *) &ssa4->sin_addr, af);
    addrcpy((void *) &remote4->sin_addr, (void *) remoteaddress, af);
    remote4->sin_port = htons(remoteport);
    len = sizeof (struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    addrcpy((void *) &local6->sin6_addr, (void *) &ssa6->sin6_addr, af);
    addrcpy((void *) &remote6->sin6_addr, (void *) remoteaddress, af);
    remote6->sin6_port = htons(remoteport);
    len = sizeof (struct sockaddr_in6);
    break;
#endif
  }

  if (bind(s, (struct sockaddr *) &local, len)) {
    display_clear();
    perror("bind()");
    exit(EXIT_FAILURE);
  }

  if (getsockname(s, (struct sockaddr *) &local, &len)) {
    display_clear();
    perror("getsockname()");
    exit(EXIT_FAILURE);
  }

  opt = 1;
  if (ioctl(s, FIONBIO, &opt)) {
    display_clear();
    perror("ioctl FIONBIO");
    exit(EXIT_FAILURE);
  }

  switch (af) {
  case AF_INET:
    if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl))) {
      display_clear();
      perror("setsockopt IP_TTL");
      exit(EXIT_FAILURE);
    }
    if (setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof (tos))) {
      display_clear();
      perror("setsockopt IP_TOS");
      exit(EXIT_FAILURE);
    }
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl))) {
      display_clear();
      perror("setsockopt IP_TTL");
      exit(EXIT_FAILURE);
    }
    break;
#endif
  }

#ifdef SO_MARK
    if (mark >= 0 && setsockopt( s, SOL_SOCKET, SO_MARK, &mark, sizeof mark ) ) {
      perror( "setsockopt SO_MARK" );
      exit( EXIT_FAILURE );
    }
#endif

  switch (local.ss_family) {
  case AF_INET:
    port = ntohs(local4->sin_port);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    port = ntohs(local6->sin6_port);
    break;
#endif
  default:
    display_clear();
    perror("unknown AF?");
    exit(EXIT_FAILURE);
  }

  save_sequence(index, port);
  gettimeofday(&sequence[port].time, NULL);
  sequence[port].socket = s;

  connect(s, (struct sockaddr *) &remote, len);
}

/*  Attempt to connect to a SCTP port with a TTL */
void net_send_sctp(int index)
{
  int ttl, s;
  int opt = 1;
  int port;
  struct sockaddr_storage local;
  struct sockaddr_storage remote;
  struct sockaddr_in *local4 = (struct sockaddr_in *) &local;
  struct sockaddr_in6 *local6 = (struct sockaddr_in6 *) &local;
  struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
  struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
  socklen_t len;

  ttl = index + 1;

  s = socket(af, SOCK_STREAM, IPPROTO_SCTP);
  if (s < 0) {
    display_clear();
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  memset(&local, 0, sizeof (local));
  memset(&remote, 0, sizeof (remote));
  local.ss_family = af;
  remote.ss_family = af;

  switch (af) {
  case AF_INET:
    addrcpy((void *) &local4->sin_addr, (void *) &ssa4->sin_addr, af);
    addrcpy((void *) &remote4->sin_addr, (void *) remoteaddress, af);
    remote4->sin_port = htons(remoteport);
    len = sizeof (struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    addrcpy((void *) &local6->sin6_addr, (void *) &ssa6->sin6_addr, af);
    addrcpy((void *) &remote6->sin6_addr, (void *) remoteaddress, af);
    remote6->sin6_port = htons(remoteport);
    len = sizeof (struct sockaddr_in6);
    break;
#endif
  }

  if (bind(s, (struct sockaddr *) &local, len)) {
    display_clear();
    perror("bind()");
    exit(EXIT_FAILURE);
  }

  if (getsockname(s, (struct sockaddr *) &local, &len)) {
    display_clear();
    perror("getsockname()");
    exit(EXIT_FAILURE);
  }

  opt = 1;
  if (ioctl(s, FIONBIO, &opt)) {
    display_clear();
    perror("ioctl FIONBIO");
    exit(EXIT_FAILURE);
  }

  switch (af) {
  case AF_INET:
    if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl))) {
      display_clear();
      perror("setsockopt IP_TTL");
      exit(EXIT_FAILURE);
    }
    if (setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof (tos))) {
      display_clear();
      perror("setsockopt IP_TOS");
      exit(EXIT_FAILURE);
    }
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl))) {
      display_clear();
      perror("setsockopt IP_TTL");
      exit(EXIT_FAILURE);
    }
    break;
#endif
  }

#ifdef SO_MARK
    if (mark >= 0 && setsockopt( s, SOL_SOCKET, SO_MARK, &mark, sizeof mark ) ) {
      perror( "setsockopt SO_MARK" );
      exit( EXIT_FAILURE );
    }
#endif

  switch (local.ss_family) {
  case AF_INET:
    port = ntohs(local4->sin_port);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    port = ntohs(local6->sin6_port);
    break;
#endif
  default:
    display_clear();
    perror("unknown AF?");
    exit(EXIT_FAILURE);
  }

  save_sequence(index, port);
  gettimeofday(&sequence[port].time, NULL);
  sequence[port].socket = s;

  connect(s, (struct sockaddr *) &remote, len);
}

/*  Attempt to find the host at a particular number of hops away  */
void net_send_query(int index) 
{
  if (mtrtype == IPPROTO_TCP) {
    net_send_tcp(index);
    return;
  }
  
  if (mtrtype == IPPROTO_SCTP) {
    net_send_sctp(index);
    return;
  }

  /*ok  char packet[sizeof(struct IPHeader) + sizeof(struct ICMPHeader)];*/
  char packet[MAXPACKET];
  struct IPHeader *ip = (struct IPHeader *) packet;
  struct ICMPHeader *icmp = NULL;
  struct UDPHeader *udp = NULL;
  struct UDPv4PHeader *udpp = NULL;
  uint16 checksum_result;
  uint16 mypid;

  /*ok  int packetsize = sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + datasize;*/
  int rv;
  static int first=1;
  int ttl, iphsize = 0, echotype = 0, salen = 0;

  ttl = index + 1;

#ifdef ENABLE_IPV6
  /* offset for ipv6 checksum calculation */
  int offset = 6;
#endif

  if ( packetsize < MINPACKET ) packetsize = MINPACKET;
  if ( packetsize > MAXPACKET ) packetsize = MAXPACKET;
  if ( mtrtype == IPPROTO_UDP && remoteport && packetsize < (MINPACKET + 2)) {
    packetsize = MINPACKET + 2;
  }

  memset(packet, (unsigned char) abs(bitpattern), abs(packetsize));

  switch ( af ) {
  case AF_INET:
#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
    iphsize = 0;
    if ( setsockopt( sendsock, IPPROTO_IP, IP_TOS, &tos, sizeof tos ) ) {
      perror( "setsockopt IP_TOS" );
      exit( EXIT_FAILURE );
    }    
    if ( setsockopt( sendsock, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl ) ) {
      perror( "setsockopt IP_TTL" );
      exit( EXIT_FAILURE );
    }    
#else
    iphsize = sizeof (struct IPHeader);

  ip->version = 0x45;
  ip->tos = tos;
  ip->len = BSDfix ? abs(packetsize): htons (abs(packetsize));
  ip->id = 0;
  ip->frag = 0;    /* 1, if want to find mtu size? Min */
    ip->ttl = ttl;
  ip->protocol = mtrtype;
  ip->check = 0;

  /* BSD needs the source address here, Linux & others do not... */
    addrcpy( (void *) &(ip->saddr), (void *) &(ssa4->sin_addr), AF_INET );
    addrcpy( (void *) &(ip->daddr), (void *) remoteaddress, AF_INET );
#endif
    echotype = ICMP_ECHO;
    salen = sizeof (struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    iphsize = 0;
    if ( setsockopt( sendsock, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                     &ttl, sizeof ttl ) ) {
      perror( "setsockopt IPV6_UNICAST_HOPS" );
      exit( EXIT_FAILURE);
    }
    echotype = ICMP6_ECHO_REQUEST;
    salen = sizeof (struct sockaddr_in6);
    break;
#endif
  }

#ifdef SO_MARK
    if (mark >= 0 && setsockopt( sendsock, SOL_SOCKET, SO_MARK, &mark, sizeof mark ) ) {
      perror( "setsockopt SO_MARK" );
      exit( EXIT_FAILURE );
    }
#endif

  switch ( mtrtype ) {
  case IPPROTO_ICMP:
    icmp = (struct ICMPHeader *)(packet + iphsize);
    icmp->type     = echotype;
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->id       = getpid();
    icmp->sequence = new_sequence(index);
    icmp->checksum = checksum(icmp, abs(packetsize) - iphsize);
    
    gettimeofday(&sequence[icmp->sequence].time, NULL);
    break;

  case IPPROTO_UDP:
    udp = (struct UDPHeader *)(packet + iphsize);
    udp->checksum  = 0;
    if (!localport) {
      mypid = (uint16)getpid();
      if (mypid < MinPort)
        mypid += MinPort;
    } else {
      mypid = (uint16)localport;
    }
    udp->srcport = htons(mypid);
    udp->length = htons(abs(packetsize) - iphsize);

    if (!remoteport) {
      udp->dstport = new_sequence(index);
      gettimeofday(&sequence[udp->dstport].time, NULL);
      udp->dstport = htons(udp->dstport);
    } else {
      // keep dstport constant, stuff sequence into the checksum
      udp->dstport = htons(remoteport);
      udp->checksum = new_sequence(index);
      gettimeofday(&sequence[udp->checksum].time, NULL);
      udp->checksum = htons(udp->checksum);
    }
    break;
  }

  switch ( af ) {
  case AF_INET:
    switch ( mtrtype ) {
    case IPPROTO_UDP:
      /* checksum is not mandatory. only calculate if we know ip->saddr */
      if (udp->checksum) {
        udpp = (struct UDPv4PHeader *)(malloc(sizeof(struct UDPv4PHeader)));
        udpp->saddr = ip->saddr;
        udpp->daddr = ip->daddr;
        udpp->protocol = ip->protocol;
        udpp->len = udp->length;
        checksum_result = udp_checksum(udpp, udp, sizeof(struct UDPv4PHeader), abs(packetsize) - iphsize, 1);
        packet[iphsize + sizeof(struct UDPHeader)] = ((char *)&checksum_result)[0];
        packet[iphsize + sizeof(struct UDPHeader) + 1] = ((char *)&checksum_result)[1];
      } else if (ip->saddr) {
        udpp = (struct UDPv4PHeader *)(malloc(sizeof(struct UDPv4PHeader)));
        udpp->saddr = ip->saddr;
        udpp->daddr = ip->daddr;
        udpp->protocol = ip->protocol;
        udpp->len = udp->length;
        udp->checksum = udp_checksum(udpp, udp, sizeof(struct UDPv4PHeader), abs(packetsize) - iphsize, 0);
      }
      break;
    }

    ip->check = checksum(packet, abs(packetsize));
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    switch ( mtrtype ) {
    case IPPROTO_UDP:
      /* kernel checksum calculation */
      if (udp->checksum) {
        offset = sizeof(struct UDPHeader);
      }
      if ( setsockopt(sendsock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) ) {
        perror( "setsockopt IPV6_CHECKSUM" );
        exit( EXIT_FAILURE);
      }
      break;
    }
    break;
#endif
  }

  rv = sendto(sendsock, packet, abs(packetsize), 0, 
	      remotesockaddr, salen);
  if (first && (rv < 0) && ((errno == EINVAL) || (errno == EMSGSIZE))) {
    /* Try the first packet again using host byte order. */
    ip->len = abs (packetsize);
    rv = sendto(sendsock, packet, abs(packetsize), 0, 
		remotesockaddr, salen);
    if (rv >= 0) {
      BSDfix = 1;
    }
  }
  first = 0;
}


/*   We got a return on something we sent out.  Record the address and
     time.  */
void net_process_ping(int seq, struct mplslen mpls, void * addr, struct timeval now) 
{
  int index;
  int totusec;
  int oldavg;	/* usedByMin */
  int oldjavg;	/* usedByMin */
  int i;	/* usedByMin */
#ifdef ENABLE_IPV6
  char addrcopy[sizeof(struct in6_addr)];
#else
  char addrcopy[sizeof(struct in_addr)];
#endif

  /* Copy the from address ASAP because it can be overwritten */
  addrcpy( (void *) &addrcopy, addr, af );

  if (seq < 0 || seq >= MaxSequence)
    return;

  if (!sequence[seq].transit)
    return;
  sequence[seq].transit = 0;

  if (sequence[seq].socket > 0) {
    close(sequence[seq].socket);
    sequence[seq].socket = 0;
  }

  index = sequence[seq].index;

  totusec = (now.tv_sec  - sequence[seq].time.tv_sec ) * 1000000 +
            (now.tv_usec - sequence[seq].time.tv_usec);
  /* impossible? if( totusec < 0 ) totusec = 0 */;

  if ( addrcmp( (void *) &(host[index].addr),
		(void *) &unspec_addr, af ) == 0 ) {
    /* should be out of if as addr can change */
    addrcpy( (void *) &(host[index].addr), addrcopy, af );
    host[index].mpls = mpls;
    display_rawhost(index, (void *) &(host[index].addr));

  /* multi paths */
    addrcpy( (void *) &(host[index].addrs[0]), addrcopy, af );
    host[index].mplss[0] = mpls;
  } else {
    for( i=0; i<MAXPATH; ) {
      if( addrcmp( (void *) &(host[index].addrs[i]), (void *) &addrcopy,
                   af ) == 0 ||
          addrcmp( (void *) &(host[index].addrs[i]),
		   (void *) &unspec_addr, af ) == 0 ) break;
      i++;
    }
    if( addrcmp( (void *) &(host[index].addrs[i]), addrcopy, af ) != 0 && 
        i<MAXPATH ) {
      addrcpy( (void *) &(host[index].addrs[i]), addrcopy, af );
      host[index].mplss[i] = mpls;
      display_rawhost(index, (void *) &(host[index].addrs[i]));
    }
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
  oldavg = host[index].avg;
  host[index].avg += (totusec - oldavg +.0) / host[index].returned;
  host[index].var += (totusec - oldavg +.0) * (totusec - host[index].avg) / 1000000;

  oldjavg = host[index].javg;
  host[index].javg += (host[index].jitter - oldjavg) / host[index].returned;
  /* below algorithm is from rfc1889, A.8 */
  host[index].jinta += host[index].jitter - ((host[index].jinta + 8) >> 4);

  if ( host[index].returned > 1 )
  host[index].gmean = pow( (double) host[index].gmean, (host[index].returned-1.0)/host[index].returned )
			* pow( (double) totusec, 1.0/host[index].returned );
  host[index].sent = 0;
  host[index].up = 1;
  host[index].transit = 0;

  net_save_return(index, sequence[seq].saved_seq, totusec);
  display_rawping(index, totusec, seq);
}


/*  We know a packet has come in, because the main select loop has called us,
    now we just need to read it, see if it is for us, and if it is a reply 
    to something we sent, then call net_process_ping()  */
void net_process_return(void) 
{
  char packet[MAXPACKET];
#ifdef ENABLE_IPV6
  struct sockaddr_storage fromsockaddr_struct;
  struct sockaddr_in6 * fsa6 = (struct sockaddr_in6 *) &fromsockaddr_struct;
#else
  struct sockaddr_in fromsockaddr_struct;
#endif
  struct sockaddr * fromsockaddr = (struct sockaddr *) &fromsockaddr_struct;
  struct sockaddr_in * fsa4 = (struct sockaddr_in *) &fromsockaddr_struct;
  socklen_t fromsockaddrsize;
  int num;
  struct ICMPHeader *header = NULL;
  struct UDPHeader *udpheader = NULL;
  struct TCPHeader *tcpheader = NULL;
  struct SCTPHeader *sctpheader = NULL;
  struct timeval now;
  ip_t * fromaddress = NULL;
  int echoreplytype = 0, timeexceededtype = 0, unreachabletype = 0;
  int sequence = 0;

  /* MPLS decoding */
  struct mplslen mpls;
  mpls.labels = 0;

  gettimeofday(&now, NULL);
  switch ( af ) {
  case AF_INET:
    fromsockaddrsize = sizeof (struct sockaddr_in);
    fromaddress = (ip_t *) &(fsa4->sin_addr);
    echoreplytype = ICMP_ECHOREPLY;
    timeexceededtype = ICMP_TIME_EXCEEDED;
    unreachabletype = ICMP_UNREACHABLE;
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    fromsockaddrsize = sizeof (struct sockaddr_in6);
    fromaddress = (ip_t *) &(fsa6->sin6_addr);
    echoreplytype = ICMP6_ECHO_REPLY;
    timeexceededtype = ICMP6_TIME_EXCEEDED;
    unreachabletype = ICMP6_DST_UNREACH;
    break;
#endif
  }

  num = recvfrom(recvsock, packet, MAXPACKET, 0, 
		 fromsockaddr, &fromsockaddrsize);

  switch ( af ) {
  case AF_INET:
    if((size_t) num < sizeof(struct IPHeader) + sizeof(struct ICMPHeader))
      return;
    header = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if(num < sizeof(struct ICMPHeader))
      return;

    header = (struct ICMPHeader *) packet;
    break;
#endif
  }

  switch ( mtrtype ) {
  case IPPROTO_ICMP:
    if (header->type == echoreplytype) {
      if(header->id != (uint16)getpid())
        return;

      sequence = header->sequence;
    } else if (header->type == timeexceededtype) {
      switch ( af ) {
      case AF_INET:

        if ((size_t) num < sizeof(struct IPHeader) + 
                           sizeof(struct ICMPHeader) + 
                           sizeof (struct IPHeader) + 
                           sizeof (struct ICMPHeader))
          return;
        header = (struct ICMPHeader *)(packet + sizeof (struct IPHeader) + 
                                                sizeof (struct ICMPHeader) + 
                                                sizeof (struct IPHeader));

        if(num > 160)
          decodempls(num, packet, &mpls, 156);

      break;
#ifdef ENABLE_IPV6
      case AF_INET6:
        if ( num < sizeof (struct ICMPHeader) + 
                   sizeof (struct ip6_hdr) + sizeof (struct ICMPHeader) )
          return;
        header = (struct ICMPHeader *) ( packet + 
                                         sizeof (struct ICMPHeader) +
                                         sizeof (struct ip6_hdr) );

        if(num > 140)
          decodempls(num, packet, &mpls, 136);

        break;
#endif
      }
  
      if (header->id != (uint16)getpid())
        return;
  
      sequence = header->sequence;
    }
    break;
  
  case IPPROTO_UDP:
    if (header->type == timeexceededtype || header->type == unreachabletype) {
      switch ( af ) {
      case AF_INET:

        if ((size_t) num < sizeof(struct IPHeader) +
                           sizeof(struct ICMPHeader) +
                           sizeof (struct IPHeader) +
                           sizeof (struct UDPHeader))
          return;
        udpheader = (struct UDPHeader *)(packet + sizeof (struct IPHeader) +
                                                  sizeof (struct ICMPHeader) +
                                                  sizeof (struct IPHeader));

        if(num > 160)
          decodempls(num, packet, &mpls, 156);

      break;
#ifdef ENABLE_IPV6
      case AF_INET6:
        if ( num < sizeof (struct ICMPHeader) +
                   sizeof (struct ip6_hdr) + sizeof (struct UDPHeader) )
          return;
        udpheader = (struct UDPHeader *) ( packet +
                                           sizeof (struct ICMPHeader) +
                                           sizeof (struct ip6_hdr) );

        if(num > 140)
          decodempls(num, packet, &mpls, 136);

        break;
#endif
      }
      if (remoteport && remoteport == ntohs(udpheader->dstport)) {
        sequence = ntohs(udpheader->checksum);
      } else if (!remoteport) {
        sequence = ntohs(udpheader->dstport);
      }
    }
    break;

  case IPPROTO_TCP:
    if (header->type == timeexceededtype || header->type == unreachabletype) {
      switch ( af ) {
      case AF_INET:

        if ((size_t) num < sizeof(struct IPHeader) +
                           sizeof(struct ICMPHeader) +
                           sizeof (struct IPHeader) +
                           sizeof (struct TCPHeader))
          return;
        tcpheader = (struct TCPHeader *)(packet + sizeof (struct IPHeader) +
                                                  sizeof (struct ICMPHeader) +
                                                  sizeof (struct IPHeader));

        if(num > 160)
          decodempls(num, packet, &mpls, 156);

      break;
#ifdef ENABLE_IPV6
      case AF_INET6:
        if ( num < sizeof (struct ICMPHeader) +
                   sizeof (struct ip6_hdr) + sizeof (struct TCPHeader) )
          return;
        tcpheader = (struct TCPHeader *) ( packet +
                                           sizeof (struct ICMPHeader) +
                                           sizeof (struct ip6_hdr) );

        if(num > 140)
          decodempls(num, packet, &mpls, 136);

        break;
#endif
      }
      sequence = ntohs(tcpheader->srcport);
    }
    break;
    
  case IPPROTO_SCTP:
    if (header->type == timeexceededtype || header->type == unreachabletype) {
      switch ( af ) {
      case AF_INET:

        if ((size_t) num < sizeof(struct IPHeader) +
                           sizeof(struct ICMPHeader) +
                           sizeof (struct IPHeader) +
                           sizeof (struct SCTPHeader))
          return;
        sctpheader = (struct SCTPHeader *)(packet + sizeof (struct IPHeader) +
                                                  sizeof (struct ICMPHeader) +
                                                  sizeof (struct IPHeader));

        if(num > 160)
          decodempls(num, packet, &mpls, 156);

      break;
#ifdef ENABLE_IPV6
      case AF_INET6:
        if ( num < sizeof (struct ICMPHeader) +
                   sizeof (struct ip6_hdr) + sizeof (struct SCTPHeader) )
          return;
        sctpheader = (struct SCTPHeader *) ( packet +
                                           sizeof (struct ICMPHeader) +
                                           sizeof (struct ip6_hdr) );

        if(num > 140)
          decodempls(num, packet, &mpls, 136);

        break;
#endif
      }
      sequence = ntohs(sctpheader->srcport);
    }
    break;
  }
  if (sequence)
    net_process_ping (sequence, mpls, (void *) fromaddress, now);
}


ip_t *net_addr(int at) 
{
  return (ip_t *)&(host[at].addr);
}


ip_t *net_addrs(int at, int i) 
{
  return (ip_t *)&(host[at].addrs[i]);
}

void *net_mpls(int at)
{
  return (struct mplslen *)&(host[at].mplss);
}

void *net_mplss(int at, int i)
{
  return (struct mplslen *)&(host[at].mplss[i]);
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
    return ( 1000.0 * sqrt( host[at].var/(host[at].returned -1.0) ) );
  } else {
    return( 0 );
  }
}


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


int net_max(void) 
{
  int at;
  int max;

  max = 0;
  /* for(at = 0; at < MaxHost-2; at++) { */
  for(at = 0; at < maxTTL-1; at++) {
    if ( addrcmp( (void *) &(host[at].addr),
                  (void *) remoteaddress, af ) == 0 ) {
      return at + 1;
    } else if ( addrcmp( (void *) &(host[at].addr),
			 (void *) &unspec_addr, af ) != 0 ) {
      max = at + 2;
    }
  }

  return max;
}


int net_min (void) 
{
  return ( fstTTL - 1 );
}


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


char * net_localaddr (void)
{
  return localaddr;
}


void net_end_transit(void) 
{
  int at;
  
  for(at = 0; at < MaxHost; at++) {
    host[at].transit = 0;
  }
}

int net_send_batch(void) 
{
  int n_unknown=0, i;

  /* randomized packet size and/or bit pattern if packetsize<0 and/or 
     bitpattern<0.  abs(packetsize) and/or abs(bitpattern) will be used 
  */
  if( batch_at < fstTTL ) {
    if( cpacketsize < 0 ) {
	/* Someone used a formula here that tried to correct for the 
           "end-error" in "rand()". By "end-error" I mean that if you 
           have a range for "rand()" that runs to 32768, and the 
           destination range is 10000, you end up with 4 out of 32768 
           0-2768's and only 3 out of 32768 for results 2769 .. 9999. 
           As our detination range (in the example 10000) is much 
           smaller (reasonable packet sizes), and our rand() range much 
           larger, this effect is insignificant. Oh! That other formula
           didn't work. */
      packetsize = MINPACKET + rand () % (-cpacketsize - MINPACKET);
    } else {
      packetsize = cpacketsize;
    }
    if( bitpattern < 0 ) {
      bitpattern = - (int)(256 + 255*(rand()/(RAND_MAX+0.1)));
    }
  }

  /* printf ("cpacketsize = %d, packetsize = %d\n", cpacketsize, packetsize);  */

  net_send_query(batch_at);

  for (i=fstTTL-1;i<batch_at;i++) {
    if ( addrcmp( (void *) &(host[i].addr), (void *) &unspec_addr, af ) == 0 )
      n_unknown++;

    /* The second condition in the next "if" statement was added in mtr-0.56, 
	but I don't remember why. It makes mtr stop skipping sections of unknown
	hosts. Removed in 0.65. 
	If the line proves necessary, it should at least NOT trigger that line
	when host[i].addr == 0 */
    if ( ( addrcmp( (void *) &(host[i].addr),
                    (void *) remoteaddress, af ) == 0 )
	/* || (host[i].addr == host[batch_at].addr)  */)
      n_unknown = MaxHost; /* Make sure we drop into "we should restart" */
  }

  if (	/* success in reaching target */
     ( addrcmp( (void *) &(host[batch_at].addr),
                (void *) remoteaddress, af ) == 0 ) ||
      /* fail in consecutive MAX_UNKNOWN_HOSTS (firewall?) */
      (n_unknown > MAX_UNKNOWN_HOSTS) ||
      /* or reach limit  */
      (batch_at >= maxTTL-1)) {
    numhosts = batch_at+1;
    batch_at = fstTTL - 1;
    return 1;
  }

  batch_at++;
  return 0;
}


static void set_fd_flags(int fd)
{
#if defined(HAVE_FCNTL) && defined(FD_CLOEXEC)
  int oldflags;

  if (fd < 0) return; 

  oldflags = fcntl(fd, F_GETFD);
  if (oldflags == -1) {
    perror("Couldn't get fd's flags");
    return;
  }
  if (fcntl(fd, F_SETFD, oldflags | FD_CLOEXEC))
    perror("Couldn't set fd's flags");
#endif
}

int net_preopen(void) 
{
  int trueopt = 1;

#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
  sendsock4_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  sendsock4_udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
#else
  sendsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
#endif
  if (sendsock4 < 0) 
    return -1;
#ifdef ENABLE_IPV6
  sendsock6_icmp = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  sendsock6_udp = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
#endif

#ifdef IP_HDRINCL
  /*  FreeBSD wants this to avoid sending out packets with protocol type RAW
      to the network.  */
  if (setsockopt(sendsock4, SOL_IP, IP_HDRINCL, &trueopt, sizeof(trueopt))) {
    perror("setsockopt(IP_HDRINCL,1)");
    return -1;
  }
#endif /* IP_HDRINCL */

  recvsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (recvsock4 < 0)
    return -1;
  set_fd_flags(recvsock4);
#ifdef ENABLE_IPV6
  recvsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (recvsock6 >= 0)
     set_fd_flags(recvsock6);
#endif

  return 0;
}


int net_selectsocket(void)
{
#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
  switch ( mtrtype ) {
  case IPPROTO_ICMP:
    sendsock4 = sendsock4_icmp;
    break;
  case IPPROTO_UDP:
    sendsock4 = sendsock4_udp;
    break;
  }
#endif
  if (sendsock4 < 0)
    return -1;
#ifdef ENABLE_IPV6
  switch ( mtrtype ) {
  case IPPROTO_ICMP:
    sendsock6 = sendsock6_icmp;
    break;
  case IPPROTO_UDP:
    sendsock6 = sendsock6_udp;
    break;
  }
  if ((sendsock6 < 0) && (sendsock4 < 0))
    return -1;
#endif

 return 0;
}


int net_open(struct hostent * host) 
{
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
#else
  struct sockaddr_in name_struct; 
#endif
  struct sockaddr * name = (struct sockaddr *) &name_struct;
  socklen_t len; 

  net_reset();

  remotesockaddr->sa_family = host->h_addrtype;

  switch ( host->h_addrtype ) {
  case AF_INET:
    sendsock = sendsock4;
    recvsock = recvsock4;
    addrcpy( (void *) &(rsa4->sin_addr), host->h_addr, AF_INET );
    sourceaddress = (ip_t *) &(ssa4->sin_addr);
    remoteaddress = (ip_t *) &(rsa4->sin_addr);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (sendsock6 < 0 || recvsock6 < 0) {
      fprintf( stderr, "Could not open IPv6 socket\n" );
      exit( EXIT_FAILURE );
    }
    sendsock = sendsock6;
    recvsock = recvsock6;
    addrcpy( (void *) &(rsa6->sin6_addr), host->h_addr, AF_INET6 );
    sourceaddress = (ip_t *) &(ssa6->sin6_addr);
    remoteaddress = (ip_t *) &(rsa6->sin6_addr);
    break;
#endif
  default:
    fprintf( stderr, "net_open bad address type\n" );
    exit( EXIT_FAILURE );
  }

  len = sizeof name_struct; 
  getsockname (recvsock, name, &len);
  sockaddrtop( name, localaddr, sizeof localaddr );
#if 0
  printf ("got localaddr: %s\n", localaddr); 
#endif

  return 0;
}


void net_reopen(struct hostent * addr) 
{
  int at;

  for(at = 0; at < MaxHost; at++) {
    memset(&host[at], 0, sizeof(host[at]));
  }

  remotesockaddr->sa_family = addr->h_addrtype;
  addrcpy( (void *) remoteaddress, addr->h_addr, addr->h_addrtype );

  switch ( addr->h_addrtype ) {
  case AF_INET:
    addrcpy( (void *) &(rsa4->sin_addr), addr->h_addr, AF_INET );
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    addrcpy( (void *) &(rsa6->sin6_addr), addr->h_addr, AF_INET6 );
    break;
#endif
  default:
    fprintf( stderr, "net_reopen bad address type\n" );
    exit( EXIT_FAILURE );
  }

  net_reset ();
  net_send_batch();
}


void net_reset(void) 
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
    if (sequence[at].socket > 0) {
      close(sequence[at].socket);
      sequence[at].socket = 0;
    }
  }

  gettimeofday(&reset, NULL);
}

int net_set_interfaceaddress_udp()
{
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
#else
  struct sockaddr_in name_struct;
#endif
  struct sockaddr_in *  sa4;
  struct sockaddr_in6 * sa6;
  struct sockaddr * name = (struct sockaddr *) &name_struct;
  struct sockaddr_storage remote;
  struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
  struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
  socklen_t len;
  int s;

  memset(&remote, 0, sizeof (remote));
  remote.ss_family = af;

  switch (af) {
  case AF_INET:
    addrcpy((void *) &remote4->sin_addr, (void *) remoteaddress, af);
    remote4->sin_port = htons(remoteport);
    len = sizeof (struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    addrcpy((void *) &remote6->sin6_addr, (void *) remoteaddress, af);
    remote6->sin6_port = htons(remoteport);
    len = sizeof (struct sockaddr_in6);
    break;
#endif
  }

  s = socket (af, SOCK_DGRAM, 0);
  if (s < 0) {
    perror("udp socket()");
    exit(EXIT_FAILURE);
  }

  if (connect(s, (struct sockaddr *) &remote, len)) {
    perror("udp connect() failed");
    exit(EXIT_FAILURE);
  }

  getsockname(s, name, &len);
  sockaddrtop( name, localaddr, sizeof localaddr );
  switch (af) {
  case AF_INET:
    sa4 = (struct sockaddr_in *) name;
    addrcpy((void*)&ssa4->sin_addr, (void *) &(sa4->sin_addr), af );
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    sa6 = (struct sockaddr_in6 *) name;
    addrcpy((void*)&ssa6->sin6_addr, (void *) &(sa6->sin6_addr), af );
    break;
#endif
  }
  close(s);

  return 0;
}


int net_set_interfaceaddress (char *InterfaceAddress)
{
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
#else
  struct sockaddr_in name_struct;
#endif
  struct sockaddr * name = (struct sockaddr *) &name_struct;
  socklen_t len = 0;

  if (mtrtype == IPPROTO_UDP && remoteport && !InterfaceAddress) {
    return net_set_interfaceaddress_udp();
  }
  if (!InterfaceAddress) return 0; 

  sourcesockaddr->sa_family = af;
  switch ( af ) {
  case AF_INET:
    ssa4->sin_port = 0;
    if ( inet_aton( InterfaceAddress, &(ssa4->sin_addr) ) < 1 ) {
      fprintf( stderr, "mtr: bad interface address: %s\n", InterfaceAddress );
      return( 1 );
  }
    len = sizeof (struct sockaddr);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    ssa6->sin6_port = 0;
    if ( inet_pton( af, InterfaceAddress, &(ssa6->sin6_addr) ) < 1 ) {
      fprintf( stderr, "mtr: bad interface address: %s\n", InterfaceAddress );
      return( 1 );
    }
    len = sizeof (struct sockaddr_in6);
    break;
#endif
  }

  if ( bind( sendsock, sourcesockaddr, len ) == -1 ) {
    perror("mtr: failed to bind to interface");
      return( 1 );
  }
  getsockname (sendsock, name, &len);
  sockaddrtop( name, localaddr, sizeof localaddr );
  return 0; 
}



void net_close(void)
{
  if (sendsock4 >= 0) {
    close(sendsock4_icmp);
    close(sendsock4_udp);
  }
  if (recvsock4 >= 0) close(recvsock4);
  if (sendsock6 >= 0) {
    close(sendsock6_icmp);
    close(sendsock6_udp);
  }
  if (recvsock6 >= 0) close(recvsock6);
}


int net_waitfd(void)
{
  return recvsock;
}


int* net_saved_pings(int at)
{
  return host[at].saved;
}


void net_save_increment(void)
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
  if (idx < 0 || idx >= SAVED_PINGS) {
    return;
  }
  host[at].saved[idx] = ms;
}

/* Similar to inet_ntop but uses a sockaddr as it's argument. */
void sockaddrtop( struct sockaddr * saddr, char * strptr, size_t len ) {
  struct sockaddr_in *  sa4;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 * sa6;
#endif

  switch ( saddr->sa_family ) {
  case AF_INET:
    sa4 = (struct sockaddr_in *) saddr;
    strncpy( strptr, inet_ntoa( sa4->sin_addr ), len - 1 );
    strptr[ len - 1 ] = '\0';
    return;
#ifdef ENABLE_IPV6
  case AF_INET6:
    sa6 = (struct sockaddr_in6 *) saddr;
    inet_ntop( sa6->sin6_family, &(sa6->sin6_addr), strptr, len );
    return;
#endif
  default:
    fprintf( stderr, "sockaddrtop unknown address type\n" );
    strptr[0] = '\0';
    return;
  }
}

/* Address comparison. */
int addrcmp( char * a, char * b, int af ) {
  int rc = -1;

  switch ( af ) {
  case AF_INET:
    rc = memcmp( a, b, sizeof (struct in_addr) );
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    rc = memcmp( a, b, sizeof (struct in6_addr) );
    break;
#endif
  }

  return rc;
}

/* Address copy. */
void addrcpy( char * a, char * b, int af ) {

  switch ( af ) {
  case AF_INET:
    memcpy( a, b, sizeof (struct in_addr) );
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    memcpy( a, b, sizeof (struct in6_addr) );
    break;
#endif
  }
}

/* Decode MPLS */
void decodempls(int num, char *packet, struct mplslen *mpls, int offset) {

  int i;
  unsigned int ext_ver, ext_res, ext_chk, obj_hdr_len;
  u_char obj_hdr_class, obj_hdr_type;

  /* loosely derived from the traceroute-nanog.c
   * decoding by Jorge Boncompte */
  ext_ver = packet[offset]>>4;
  ext_res = (packet[offset]&15)+ packet[offset+1];
  ext_chk = ((unsigned int)packet[offset+2]<<8)+packet[offset+3];

  /* Check for ICMP extension header */
  if (ext_ver == 2 && ext_res == 0 && ext_chk != 0 && num >= (offset+6)) {
    obj_hdr_len = ((int)packet[offset+4]<<8)+packet[offset+5];
    obj_hdr_class = packet[offset+6];
    obj_hdr_type = packet[offset+7];

    /* make sure we have an MPLS extension */
    if (obj_hdr_len >= 8 && obj_hdr_class == 1 && obj_hdr_type == 1) {
      /* how many labels do we have?  will be at least 1 */
      mpls->labels = (obj_hdr_len-4)/4;

      /* save all label objects */
      for(i=0; (i<mpls->labels) && (i < MAXLABELS) && (num >= (offset+8)+(i*4)); i++) {

        /* piece together the 20 byte label value */
        mpls->label[i] = ((unsigned long) (packet[(offset+8)+(i*4)] << 12 & 0xff000) +
            (unsigned int) (packet[(offset+9)+(i*4)] << 4 & 0xff0) +
            (packet[(offset+10)+(i*4)] >> 4 & 0xf));
        mpls->exp[i] = (packet[(offset+10)+(i*4)] >> 1) & 0x7;
        mpls->s[i] = (packet[(offset+10)+(i*4)] & 0x1); /* should be 1 if only one label */
        mpls->ttl[i] = packet[(offset+11)+(i*4)];
      }
    }
  }
}

/* Add open sockets to select() */
void net_add_fds(fd_set *writefd, int *maxfd)
{
  int at, fd;
  for (at = 0; at < MaxSequence; at++) {
    fd = sequence[at].socket;
    if (fd > 0) {
      FD_SET(fd, writefd);
      if (fd >= *maxfd)
        *maxfd = fd + 1;
    }
  }
}

/* check if we got connection or error on any fds */
void net_process_fds(fd_set *writefd)
{
  int at, fd, r;
  struct timeval now;
  uint64_t unow, utime;

  /* Can't do MPLS decoding */
  struct mplslen mpls;
  mpls.labels = 0;

  gettimeofday(&now, NULL);
  unow = now.tv_sec * 1000000L + now.tv_usec;

  for (at = 0; at < MaxSequence; at++) {
    fd = sequence[at].socket;
    if (fd > 0 && FD_ISSET(fd, writefd)) {
      r = write(fd, "G", 1);
      /* if write was successful, or connection refused we have
       * (probably) reached the remote address. Anything else happens to the
       * connection, we write it off to avoid leaking sockets */
      if (r == 1 || errno == ECONNREFUSED)
        net_process_ping(at, mpls, remoteaddress, now);
      else if (errno != EAGAIN) {
        close(fd);
        sequence[at].socket = 0;
      }
    }
    if (fd > 0) {
      utime = sequence[at].time.tv_sec * 1000000L + sequence[at].time.tv_usec;
      if (unow - utime > tcp_timeout) {
        close(fd);
        sequence[at].socket = 0;
      }
    }
  }
}

/* for GTK frontend */
void net_harvest_fds(void)
{
  fd_set writefd;
  int maxfd = 0;
  struct timeval tv;

  FD_ZERO(&writefd);
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  net_add_fds(&writefd, &maxfd);
  select(maxfd, NULL, &writefd, NULL, &tv);
  net_process_fds(&writefd);
}
