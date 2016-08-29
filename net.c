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
#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif


#include "mtr.h"
#include "net.h"
#include "display.h"
#include "dns.h"

static int packetsize;         /* packet size used by ping */
static int spacketsize;                /* packet size used by sendto */

static void sockaddrtop( struct sockaddr * saddr, char * strptr, size_t len );
static void decodempls(int, char *, struct mplslen *, int);

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

// This ifdef is unnecessary. But it should trigger errors if I forget
// an ifdef HAS_SCTP further down.  (Success! I forgot one and the compiler
// told me the line number!)
#ifdef HAS_SCTP 
/* Structure of an SCTP header */
struct SCTPHeader {
  uint16 srcport;
  uint16 dstport;
  uint32 veri_tag;
};
#endif

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
  long long ssd; /* sum of squares of differences from the current average */
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


/* BSD-derived kernels use host byte order for the IP length and 
   offset fields when using raw sockets.  We detect this automatically at 
   run-time and do the right thing. */
static int BSDfix = 0;

static struct nethost host[MaxHost];
static struct sequence sequence[MaxSequence];
static struct timeval reset = { 0, 0 };

static int    sendsock4;
static int    sendsock4_icmp;
static int    sendsock4_udp;
static int    recvsock4;
static int    sendsock6;
static int    sendsock6_icmp;
static int    sendsock6_udp;
static int    recvsock6;
static int    sendsock;
static int    recvsock;

#ifdef ENABLE_IPV6
static struct sockaddr_storage sourcesockaddr_struct;
static struct sockaddr_storage remotesockaddr_struct;
static struct sockaddr_in6 * ssa6 = (struct sockaddr_in6 *) &sourcesockaddr_struct;
static struct sockaddr_in6 * rsa6 = (struct sockaddr_in6 *) &remotesockaddr_struct;
#else
static struct sockaddr_in sourcesockaddr_struct;
static struct sockaddr_in remotesockaddr_struct;
#endif

static struct sockaddr * sourcesockaddr = (struct sockaddr *) &sourcesockaddr_struct;
static struct sockaddr * remotesockaddr = (struct sockaddr *) &remotesockaddr_struct;
static struct sockaddr_in * ssa4 = (struct sockaddr_in *) &sourcesockaddr_struct;
static struct sockaddr_in * rsa4 = (struct sockaddr_in *) &remotesockaddr_struct;

static ip_t * sourceaddress;
static ip_t * remoteaddress;

/* XXX How do I code this to be IPV6 compatible??? */
#ifdef ENABLE_IPV6
static char localaddr[INET6_ADDRSTRLEN];
#else
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
static char localaddr[INET_ADDRSTRLEN];
#endif

static int batch_at = 0;
static int numhosts = 10;

/* return the number of microseconds to wait before sending the next
   ping */
extern int calc_deltatime (float waittime)
{
  waittime /= numhosts;
  return 1000000 * waittime;
}


static int checksum(void *data, int sz) 
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
static int udp_checksum(struct mtr_ctl *ctl, void *pheader, void *udata,
			int psize, int dsize, int alt_checksum)
{
  unsigned int tsize = psize + dsize;
  char csumpacket[tsize];
  memset(csumpacket, (unsigned char) abs(ctl->bitpattern), tsize);
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


static void save_sequence(struct mtr_ctl *ctl, int index, int seq)
{
  display_rawxmit(ctl, index, seq);

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

static int new_sequence(struct mtr_ctl *ctl, int index)
{
  static int next_sequence = MinSequence;
  int seq;

  seq = next_sequence++;
  if (next_sequence >= MaxSequence)
    next_sequence = MinSequence;

  save_sequence(ctl, index, seq);

  return seq;
}

/*  Attempt to connect to a TCP port with a TTL */
static void net_send_tcp(struct mtr_ctl *ctl, int index)
{
  int ttl, s;
  int port = 0;
  int flags;
  struct sockaddr_storage local;
  struct sockaddr_storage remote;
  struct sockaddr_in *local4 = (struct sockaddr_in *) &local;
  struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *local6 = (struct sockaddr_in6 *) &local;
  struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
#endif
  socklen_t len;

  ttl = index + 1;

  s = socket(ctl->af, SOCK_STREAM, 0);
  if (s < 0) {
    display_clear(ctl);
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  memset(&local, 0, sizeof (local));
  memset(&remote, 0, sizeof (remote));
  local.ss_family = ctl->af;
  remote.ss_family = ctl->af;

  switch (ctl->af) {
  case AF_INET:
    addrcpy((void *) &local4->sin_addr, (void *) &ssa4->sin_addr, ctl->af);
    addrcpy((void *) &remote4->sin_addr, (void *) remoteaddress, ctl->af);
    remote4->sin_port = htons(ctl->remoteport);
    len = sizeof (struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    addrcpy((void *) &local6->sin6_addr, (void *) &ssa6->sin6_addr, ctl->af);
    addrcpy((void *) &remote6->sin6_addr, (void *) remoteaddress, ctl->af);
    remote6->sin6_port = htons(ctl->remoteport);
    len = sizeof (struct sockaddr_in6);
    break;
#endif
  }

  if (bind(s, (struct sockaddr *) &local, len)) {
    display_clear(ctl);
    error(EXIT_FAILURE, errno, "bind()");
  }

  if (getsockname(s, (struct sockaddr *) &local, &len)) {
    display_clear(ctl);
    error(EXIT_FAILURE, errno, "getsockname()");
  }

  //  opt = 1;
  flags = fcntl(s, F_GETFL, 0);
  if (flags < 0) {
    display_clear(ctl);
    error(EXIT_FAILURE, errno, "fcntl(F_GETFL)");
  }

  if (fcntl (s, F_SETFL, flags | O_NONBLOCK) < 0) {
    display_clear(ctl);
    error(EXIT_FAILURE, errno, "fcntl(F_SETFL, O_NONBLOCK)");
  }


  switch (ctl->af) {
  case AF_INET:
    if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl))) {
      display_clear(ctl);
      error(EXIT_FAILURE, errno, "setsockopt IP_TTL");
    }
    if (setsockopt(s, IPPROTO_IP, IP_TOS, &ctl->tos, sizeof (ctl->tos))) {
      display_clear(ctl);
      error(EXIT_FAILURE, errno, "setsockopt IP_TOS");
    }
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl))) {
      display_clear(ctl);
      error(EXIT_FAILURE, errno, "setsockopt IPPROTO_IPV6 ttl");
    }
    break;
#endif
  }

#ifdef SO_MARK
    if (ctl->mark && setsockopt( s, SOL_SOCKET, SO_MARK, &ctl->mark, sizeof ctl->mark ) ) {
      error(EXIT_FAILURE, errno, "setsockopt SO_MARK");
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
    display_clear(ctl);
    error(EXIT_FAILURE, 0, "unknown address family");
  }

  save_sequence(ctl, index, port);
  gettimeofday(&sequence[port].time, NULL);
  sequence[port].socket = s;

  connect(s, (struct sockaddr *) &remote, len);
}

#ifdef HAS_SCTP
/*  Attempt to connect to a SCTP port with a TTL */
static void net_send_sctp(struct mtr_ctl *ctl, int index)
{
  int ttl, s;
  int opt = 1;
  int port = 0;
  struct sockaddr_storage local;
  struct sockaddr_storage remote;
  struct sockaddr_in *local4 = (struct sockaddr_in *) &local;
  struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *local6 = (struct sockaddr_in6 *) &local;
  struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
#endif
  socklen_t len;

  ttl = index + 1;

  s = socket(ctl->af, SOCK_STREAM, IPPROTO_SCTP);
  if (s < 0) {
    display_clear(ctl);
    error(EXIT_FAILURE, errno, "socket()");
  }

  memset(&local, 0, sizeof (local));
  memset(&remote, 0, sizeof (remote));
  local.ss_family = ctl->af;
  remote.ss_family = ctl->af;

  switch (ctl->af) {
  case AF_INET:
    addrcpy((void *) &local4->sin_addr, (void *) &ssa4->sin_addr, ctl->af);
    addrcpy((void *) &remote4->sin_addr, (void *) remoteaddress, ctl->af);
    remote4->sin_port = htons(ctl->remoteport);
    len = sizeof (struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    addrcpy((void *) &local6->sin6_addr, (void *) &ssa6->sin6_addr, ctl->af);
    addrcpy((void *) &remote6->sin6_addr, (void *) remoteaddress, ctl->af);
    remote6->sin6_port = htons(ctl->remoteport);
    len = sizeof (struct sockaddr_in6);
    break;
#endif
  }

  if (bind(s, (struct sockaddr *) &local, len)) {
    display_clear(ctl);
    error(EXIT_FAILURE, errno, "bind()");
  }

  if (getsockname(s, (struct sockaddr *) &local, &len)) {
    display_clear(ctl);
    error(EXIT_FAILURE, errno, "getsockname()");
  }

  opt = 1;
  if (ioctl(s, FIONBIO, &opt)) {
    display_clear(ctl);
    error(EXIT_FAILURE, errno, "ioctl FIONBIO");
  }

  switch (ctl->af) {
  case AF_INET:
    if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl))) {
      display_clear(ctl);
      error(EXIT_FAILURE, errno, "setsockopt IP_TTL");
    }
    if (setsockopt(s, IPPROTO_IP, IP_TOS, &ctl->tos, sizeof (ctl->tos))) {
      display_clear(ctl);
      error(EXIT_FAILURE, errno, "setsockopt IP_TOS");
    }
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl))) {
      display_clear(ctl);
      error(EXIT_FAILURE, errno, "setsockopt IPPROTO_IPV6 ttl");
    }
    break;
#endif
  }

#ifdef SO_MARK
    if (ctl->mark && setsockopt( s, SOL_SOCKET, SO_MARK, &ctl->mark, sizeof ctl->mark ) ) {
      error(EXIT_FAILURE, errno, "setsockopt SO_MARK");
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
    display_clear(ctl);
    error(EXIT_FAILURE, 0, "unknown address family");
  }

  save_sequence(ctl, index, port);
  gettimeofday(&sequence[port].time, NULL);
  sequence[port].socket = s;

  connect(s, (struct sockaddr *) &remote, len);
}
#endif

/*  Attempt to find the host at a particular number of hops away  */
static void net_send_query(struct mtr_ctl *ctl, int index)
{
  if (ctl->mtrtype == IPPROTO_TCP) {
    net_send_tcp(ctl, index);
    return;
  }
  
#ifdef HAS_SCTP
  if (ctl->mtrtype == IPPROTO_SCTP) {
    net_send_sctp(ctl, index);
    return;
  }
#endif

  /*ok  char packet[sizeof(struct IPHeader) + sizeof(struct ICMPHeader)];*/
  char packet[MAXPACKET];
  struct IPHeader *ip = (struct IPHeader *) packet;
  struct ICMPHeader *icmp = NULL;
  struct UDPHeader *udp = NULL;
  struct UDPv4PHeader *udpp = NULL;
  uint16 checksum_result;

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
  if ( ctl->mtrtype == IPPROTO_UDP && ctl->remoteport && packetsize < (MINPACKET + 2)) {
    packetsize = MINPACKET + 2;
  }

  memset(packet, (unsigned char) abs(ctl->bitpattern), abs(packetsize));

  switch ( ctl->af ) {
  case AF_INET:
#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
    iphsize = 0;
    if ( setsockopt( sendsock, IPPROTO_IP, IP_TOS, &ctl->tos, sizeof ctl->tos ) ) {
      error(EXIT_FAILURE, errno, "setsockopt IP_TOS");
    }    
    if ( setsockopt( sendsock, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl ) ) {
      error(EXIT_FAILURE, errno, "setsockopt IP_TTL");
    }    
#else
    iphsize = sizeof (struct IPHeader);

  ip->version = 0x45;
  ip->tos = ctl->tos;
  ip->len = BSDfix ? abs(packetsize): htons (abs(packetsize));
  ip->id = 0;
  ip->frag = 0;    /* 1, if want to find mtu size? Min */
    ip->ttl = ttl;
  ip->protocol = ctl->mtrtype;
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
      error(EXIT_FAILURE, errno, "setsockopt IPV6_UNICAST_HOPS");
    }
    echotype = ICMP6_ECHO_REQUEST;
    salen = sizeof (struct sockaddr_in6);
    break;
#endif
  }

#ifdef SO_MARK
    if (ctl->mark && setsockopt( sendsock, SOL_SOCKET, SO_MARK, &ctl->mark, sizeof ctl->mark ) ) {
      error(EXIT_FAILURE, errno, "setsockopt SO_MARK");
    }
#endif

  switch ( ctl->mtrtype ) {
  case IPPROTO_ICMP:
    icmp = (struct ICMPHeader *)(packet + iphsize);
    icmp->type     = echotype;
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->id       = getpid();
    icmp->sequence = new_sequence(ctl, index);
    icmp->checksum = checksum(icmp, abs(packetsize) - iphsize);
    
    gettimeofday(&sequence[icmp->sequence].time, NULL);
    break;

  case IPPROTO_UDP:
    udp = (struct UDPHeader *)(packet + iphsize);
    udp->checksum  = 0;
    if (!ctl->localport) {
      ctl->localport = (uint16)getpid();
      if (ctl->localport < MinPort)
        ctl->localport += MinPort;
    }
    udp->srcport = htons(ctl->localport);
    udp->length = htons(abs(packetsize) - iphsize);

    if (!ctl->remoteport) {
      udp->dstport = new_sequence(ctl, index);
      gettimeofday(&sequence[udp->dstport].time, NULL);
      udp->dstport = htons(udp->dstport);
    } else {
      // keep dstport constant, stuff sequence into the checksum
      udp->dstport = htons(ctl->remoteport);
      udp->checksum = new_sequence(ctl, index);
      gettimeofday(&sequence[udp->checksum].time, NULL);
      udp->checksum = htons(udp->checksum);
    }
    break;
  }

  switch ( ctl->af ) {
  case AF_INET:
    switch ( ctl->mtrtype ) {
    case IPPROTO_UDP:
      /* checksum is not mandatory. only calculate if we know ip->saddr */
      if (udp->checksum) {
        udpp = (struct UDPv4PHeader *)(malloc(sizeof(struct UDPv4PHeader)));
        udpp->saddr = ip->saddr;
        udpp->daddr = ip->daddr;
        udpp->protocol = ip->protocol;
        udpp->len = udp->length;
        checksum_result = udp_checksum(ctl, udpp, udp, sizeof(struct UDPv4PHeader), abs(packetsize) - iphsize, 1);
        packet[iphsize + sizeof(struct UDPHeader)] = ((char *)&checksum_result)[0];
        packet[iphsize + sizeof(struct UDPHeader) + 1] = ((char *)&checksum_result)[1];
      } else if (ip->saddr) {
        udpp = (struct UDPv4PHeader *)(malloc(sizeof(struct UDPv4PHeader)));
        udpp->saddr = ip->saddr;
        udpp->daddr = ip->daddr;
        udpp->protocol = ip->protocol;
        udpp->len = udp->length;
        udp->checksum = udp_checksum(ctl, udpp, udp, sizeof(struct UDPv4PHeader), abs(packetsize) - iphsize, 0);
      }
      break;
    }

    ip->check = checksum(packet, abs(packetsize));
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    switch ( ctl->mtrtype ) {
    case IPPROTO_UDP:
      /* kernel checksum calculation */
      if (udp->checksum) {
        offset = sizeof(struct UDPHeader);
      }
      if ( setsockopt(sendsock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) ) {
        error(EXIT_FAILURE, errno, "setsockopt IPV6_CHECKSUM");
      }
      break;
    }
    break;
#endif
  }

  /* sendto() assumes packet length includes the IPv4 header but not the 
     IPv6 header. */
  spacketsize = abs(packetsize)
#ifdef ENABLE_IPV6
                - ( ( ctl->af == AF_INET ) ? 0 : sizeof (struct ip6_hdr) )
#endif
                ;

  rv = sendto(sendsock, packet, spacketsize, 0, remotesockaddr, salen);
  if (first && (rv < 0) && ((errno == EINVAL) || (errno == EMSGSIZE))) {
    /* Try the first packet again using host byte order. */
    ip->len = spacketsize;
    rv = sendto(sendsock, packet, spacketsize, 0, remotesockaddr, salen);
    if (rv >= 0) {
      BSDfix = 1;
    }
  }
  first = 0;
}


/*   We got a return on something we sent out.  Record the address and
     time.  */
static void net_process_ping(struct mtr_ctl *ctl, int seq, struct mplslen mpls,
			     void *addr, struct timeval now)
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
  addrcpy( (void *) &addrcopy, addr, ctl->af );

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
		(void *) &ctl->unspec_addr, ctl->af ) == 0 ) {
    /* should be out of if as addr can change */
    addrcpy( (void *) &(host[index].addr), addrcopy, ctl->af );
    host[index].mpls = mpls;
    display_rawhost(ctl, index, (void *) &(host[index].addr));

  /* multi paths */
    addrcpy( (void *) &(host[index].addrs[0]), addrcopy, ctl->af );
    host[index].mplss[0] = mpls;
  } else {
    for( i=0; i<MAXPATH; ) {
      if( addrcmp( (void *) &(host[index].addrs[i]), (void *) &addrcopy,
                   ctl->af ) == 0 ||
          addrcmp( (void *) &(host[index].addrs[i]),
		   (void *) &ctl->unspec_addr, ctl->af ) == 0 ) break;
      i++;
    }
    if( addrcmp( (void *) &(host[index].addrs[i]), addrcopy, ctl->af ) != 0 && 
        i<MAXPATH ) {
      addrcpy( (void *) &(host[index].addrs[i]), addrcopy, ctl->af );
      host[index].mplss[i] = mpls;
      display_rawhost(ctl, index, (void *) &(host[index].addrs[i]));
    }
  }

  host[index].jitter = totusec - host[index].last;
  if (host[index].jitter < 0 ) host[index].jitter = - host[index].jitter;
  host[index].last = totusec;

  if (host[index].returned < 1) {
    host[index].best = host[index].worst = host[index].gmean = totusec;
    host[index].avg  = host[index].ssd  = 0;

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
  host[index].ssd += (totusec - oldavg +.0) * (totusec - host[index].avg);

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
  display_rawping(ctl, index, totusec, seq);
}


/*  We know a packet has come in, because the main select loop has called us,
    now we just need to read it, see if it is for us, and if it is a reply 
    to something we sent, then call net_process_ping()  */
extern void net_process_return(struct mtr_ctl *ctl)
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
  ssize_t num;
  struct ICMPHeader *header = NULL;
  struct UDPHeader *udpheader = NULL;
  struct TCPHeader *tcpheader = NULL;
#ifdef HAS_SCTP
  struct SCTPHeader *sctpheader = NULL;
#endif
  struct timeval now;
  ip_t * fromaddress = NULL;
  int echoreplytype = 0, timeexceededtype = 0, unreachabletype = 0;
  int seq_num = 0;

  /* MPLS decoding */
  struct mplslen mpls;
  mpls.labels = 0;

  gettimeofday(&now, NULL);
  switch ( ctl->af ) {
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
  if(num < 0) {
    error(EXIT_FAILURE, errno, "recvfrom failed");
  }

  switch ( ctl->af ) {
  case AF_INET:
    if((size_t) num < sizeof(struct IPHeader) + sizeof(struct ICMPHeader))
      return;
    header = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if((size_t) num < sizeof(struct ICMPHeader))
      return;

    header = (struct ICMPHeader *) packet;
    break;
#endif
  }

  switch ( ctl->mtrtype ) {
  case IPPROTO_ICMP:
    if (header->type == echoreplytype) {
      if(header->id != (uint16)getpid())
        return;

      seq_num = header->sequence;
    } else if (header->type == timeexceededtype) {
      switch ( ctl->af ) {
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
        if ((size_t) num < sizeof (struct ICMPHeader) +
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
  
      seq_num = header->sequence;
    }
    break;
  
  case IPPROTO_UDP:
    if (header->type == timeexceededtype || header->type == unreachabletype) {
      switch ( ctl->af ) {
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
        if ((size_t) num < sizeof (struct ICMPHeader) +
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
      if (ntohs(udpheader->srcport) != (uint16)ctl->localport)
        return;

      if (ctl->remoteport && ctl->remoteport == ntohs(udpheader->dstport)) {
        seq_num = ntohs(udpheader->checksum);
      } else if (!ctl->remoteport) {
        seq_num = ntohs(udpheader->dstport);
      }
    }
    break;

  case IPPROTO_TCP:
    if (header->type == timeexceededtype || header->type == unreachabletype) {
      switch ( ctl->af ) {
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
        if ((size_t) num < sizeof (struct ICMPHeader) +
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
      seq_num = ntohs(tcpheader->srcport);
    }
    break;

#ifdef HAS_SCTP
  case IPPROTO_SCTP:
    if (header->type == timeexceededtype || header->type == unreachabletype) {
      switch ( ctl->af ) {
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
        if ((size_t) num < sizeof (struct ICMPHeader) +
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
      seq_num = ntohs(sctpheader->srcport);
    }
    break;
#endif
  }
  if (seq_num)
    net_process_ping (ctl, seq_num, mpls, (void *) fromaddress, now);
}


extern ip_t *net_addr(int at) 
{
  return (ip_t *)&(host[at].addr);
}


extern ip_t *net_addrs(int at, int i) 
{
  return (ip_t *)&(host[at].addrs[i]);
}

extern void *net_mpls(int at)
{
  return (struct mplslen *)&(host[at].mplss);
}

extern void *net_mplss(int at, int i)
{
  return (struct mplslen *)&(host[at].mplss[i]);
}

extern int net_loss(int at) 
{
  if ((host[at].xmit - host[at].transit) == 0) 
    return 0;
  /* times extra 1000 */
  return 1000*(100 - (100.0 * host[at].returned / (host[at].xmit - host[at].transit)) );
}


extern int net_drop(int at) 
{
  return (host[at].xmit - host[at].transit) - host[at].returned;
}


extern int net_last(int at) 
{
  return (host[at].last);
}


extern int net_best(int at) 
{
  return (host[at].best);
}


extern int net_worst(int at) 
{
  return (host[at].worst);
}


extern int net_avg(int at) 
{
  return (host[at].avg);
}


extern int net_gmean(int at) 
{
  return (host[at].gmean);
}


extern int net_stdev(int at) 
{
  if( host[at].returned > 1 ) {
    return ( sqrt( host[at].ssd/(host[at].returned -1.0) ) );
  } else {
    return( 0 );
  }
}


extern int net_jitter(int at) 
{ 
  return (host[at].jitter); 
}


extern int net_jworst(int at) 
{ 
  return (host[at].jworst); 
}


extern int net_javg(int at) 
{ 
  return (host[at].javg); 
}


extern int net_jinta(int at) 
{ 
  return (host[at].jinta); 
}


extern int net_max(struct mtr_ctl *ctl)
{
  int at;
  int max;

  max = 0;
  /* for(at = 0; at < MaxHost-2; at++) { */
  for(at = 0; at < ctl->maxTTL-1; at++) {
    if ( addrcmp( (void *) &(host[at].addr),
                  (void *) remoteaddress, ctl->af ) == 0 ) {
      return at + 1;
    } else if ( addrcmp( (void *) &(host[at].addr),
			 (void *) &ctl->unspec_addr, ctl->af ) != 0 ) {
      max = at + 2;
    }
  }

  return max;
}


extern int net_min (struct mtr_ctl *ctl)
{
  return ( ctl->fstTTL - 1 );
}


extern int net_returned(int at) 
{ 
  return host[at].returned;
}


extern int net_xmit(int at) 
{ 
  return host[at].xmit;
}


extern int net_up(int at) 
{
   return host[at].up;
}


extern char * net_localaddr (void)
{
  return localaddr;
}


extern void net_end_transit(void) 
{
  int at;
  
  for(at = 0; at < MaxHost; at++) {
    host[at].transit = 0;
  }
}

extern int net_send_batch(struct mtr_ctl *ctl)
{
  int n_unknown=0, i;

  /* randomized packet size and/or bit pattern if packetsize<0 and/or 
     bitpattern<0.  abs(packetsize) and/or abs(bitpattern) will be used 
  */
  if( batch_at < ctl->fstTTL ) {
    if( ctl->cpacketsize < 0 ) {
	/* Someone used a formula here that tried to correct for the 
           "end-error" in "rand()". By "end-error" I mean that if you 
           have a range for "rand()" that runs to 32768, and the 
           destination range is 10000, you end up with 4 out of 32768 
           0-2768's and only 3 out of 32768 for results 2769 .. 9999. 
           As our detination range (in the example 10000) is much 
           smaller (reasonable packet sizes), and our rand() range much 
           larger, this effect is insignificant. Oh! That other formula
           didn't work. */
      packetsize = MINPACKET + rand () % (- ctl->cpacketsize - MINPACKET);
    } else {
      packetsize = ctl->cpacketsize;
    }
    if(ctl->bitpattern < 0 ) {
      ctl->bitpattern = - (int)(256 + 255*(rand()/(RAND_MAX+0.1)));
    }
  }

  /* printf ("cpacketsize = %d, packetsize = %d\n", cpacketsize, packetsize);  */

  net_send_query(ctl, batch_at);

  for (i=ctl->fstTTL-1;i<batch_at;i++) {
    if ( addrcmp( (void *) &(host[i].addr), (void *) &ctl->unspec_addr, ctl->af ) == 0 )
      n_unknown++;

    /* The second condition in the next "if" statement was added in mtr-0.56, 
	but I don't remember why. It makes mtr stop skipping sections of unknown
	hosts. Removed in 0.65. 
	If the line proves necessary, it should at least NOT trigger that line
	when host[i].addr == 0 */
    if ( ( addrcmp( (void *) &(host[i].addr),
                    (void *) remoteaddress, ctl->af ) == 0 )
	/* || (host[i].addr == host[batch_at].addr)  */)
      n_unknown = MaxHost; /* Make sure we drop into "we should restart" */
  }

  if (	/* success in reaching target */
     ( addrcmp( (void *) &(host[batch_at].addr),
                (void *) remoteaddress, ctl->af ) == 0 ) ||
      /* fail in consecutive maxUnknown (firewall?) */
      (n_unknown > ctl->maxUnknown) ||
      /* or reach limit  */
      (batch_at >= ctl->maxTTL-1)) {
    numhosts = batch_at+1;
    batch_at = ctl->fstTTL - 1;
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
    error(0, errno, "Couldn't get fd's flags");
    return;
  }
  if (fcntl(fd, F_SETFD, oldflags | FD_CLOEXEC))
    error(0, errno, "Couldn't set fd's flags");
#endif
}

extern int net_preopen(void) 
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
    error(0, errno, "setsockopt IP_HDRINCL");
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


extern int net_selectsocket(struct mtr_ctl *ctl)
{
#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
  switch ( ctl->mtrtype ) {
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
  switch ( ctl->mtrtype ) {
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


extern int net_open(struct mtr_ctl *ctl, struct hostent * hostent)
{
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
#else
  struct sockaddr_in name_struct; 
#endif
  struct sockaddr * name = (struct sockaddr *) &name_struct;
  socklen_t len; 

  net_reset(ctl);

  remotesockaddr->sa_family = hostent->h_addrtype;

  switch ( hostent->h_addrtype ) {
  case AF_INET:
    sendsock = sendsock4;
    recvsock = recvsock4;
    addrcpy( (void *) &(rsa4->sin_addr), hostent->h_addr, AF_INET );
    sourceaddress = (ip_t *) &(ssa4->sin_addr);
    remoteaddress = (ip_t *) &(rsa4->sin_addr);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (sendsock6 < 0 || recvsock6 < 0) {
      error(EXIT_FAILURE, errno, "Could not open IPv6 socket");
    }
    sendsock = sendsock6;
    recvsock = recvsock6;
    addrcpy( (void *) &(rsa6->sin6_addr), hostent->h_addr, AF_INET6 );
    sourceaddress = (ip_t *) &(ssa6->sin6_addr);
    remoteaddress = (ip_t *) &(rsa6->sin6_addr);
    break;
#endif
  default:
    error(EXIT_FAILURE, 0, "net_open bad address type");
  }

  len = sizeof name_struct; 
  getsockname (recvsock, name, &len);
  sockaddrtop( name, localaddr, sizeof localaddr );
#if 0
  printf ("got localaddr: %s\n", localaddr); 
#endif

  return 0;
}


extern void net_reopen(struct mtr_ctl *ctl, struct hostent * addr)
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
    error(EXIT_FAILURE, 0, "net_reopen bad address type");
  }

  net_reset (ctl);
  net_send_batch(ctl);
}


extern void net_reset(struct mtr_ctl *ctl)
{
  int at;
  int i;

  batch_at = ctl->fstTTL - 1;	/* above replacedByMin */
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
    host[at].ssd = 0;
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

static int net_set_interfaceaddress_udp(struct mtr_ctl *ctl)
{
  struct sockaddr_in *  sa4;
  struct sockaddr_storage remote;
  struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
  struct sockaddr_in6 * sa6;
  struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
#else
  struct sockaddr_in name_struct;
#endif
  struct sockaddr * name = (struct sockaddr *) &name_struct;
  socklen_t len;
  int s;

  memset(&remote, 0, sizeof (remote));
  remote.ss_family = ctl->af;

  switch (ctl->af) {
  case AF_INET:
    addrcpy((void *) &remote4->sin_addr, (void *) remoteaddress, ctl->af);
    remote4->sin_port = htons(ctl->remoteport);
    len = sizeof (struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    addrcpy((void *) &remote6->sin6_addr, (void *) remoteaddress, ctl->af);
    remote6->sin6_port = htons(ctl->remoteport);
    len = sizeof (struct sockaddr_in6);
    break;
#endif
  }

  s = socket (ctl->af, SOCK_DGRAM, 0);
  if (s < 0) {
    error(EXIT_FAILURE, errno, "udp socket()");
  }

  if (connect(s, (struct sockaddr *) &remote, len)) {
    error(EXIT_FAILURE, errno, "udp connect()");
  }

  getsockname(s, name, &len);
  sockaddrtop( name, localaddr, sizeof localaddr );
  switch (ctl->af) {
  case AF_INET:
    sa4 = (struct sockaddr_in *) name;
    addrcpy((void*)&ssa4->sin_addr, (void *) &(sa4->sin_addr), ctl->af );
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    sa6 = (struct sockaddr_in6 *) name;
    addrcpy((void*)&ssa6->sin6_addr, (void *) &(sa6->sin6_addr), ctl->af );
    break;
#endif
  }
  close(s);

  return 0;
}


extern int net_set_interfaceaddress (struct mtr_ctl *ctl)
{
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
#else
  struct sockaddr_in name_struct;
#endif
  struct sockaddr * name = (struct sockaddr *) &name_struct;
  socklen_t len = 0;

  if (ctl->mtrtype == IPPROTO_UDP && ctl->remoteport && !ctl->InterfaceAddress) {
    return net_set_interfaceaddress_udp(ctl);
  }
  if (!ctl->InterfaceAddress) return 0; 

  sourcesockaddr->sa_family = ctl->af;
  switch ( ctl->af ) {
  case AF_INET:
    ssa4->sin_port = 0;
    if ( inet_aton( ctl->InterfaceAddress, &(ssa4->sin_addr) ) < 1 ) {
      error(0, 0, "bad interface address: %s", ctl->InterfaceAddress);
      return( 1 );
  }
    len = sizeof (struct sockaddr);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    ssa6->sin6_port = 0;
    if ( inet_pton( ctl->af, ctl->InterfaceAddress, &(ssa6->sin6_addr) ) < 1 ) {
      error(0, 0, "bad interface address: %s", ctl->InterfaceAddress);
      return( 1 );
    }
    len = sizeof (struct sockaddr_in6);
    break;
#endif
  }

  if ( bind( sendsock, sourcesockaddr, len ) == -1 ) {
    error(0, 0, "failed to bind to interface: %s", ctl->InterfaceAddress);
      return( 1 );
  }
  getsockname (sendsock, name, &len);
  sockaddrtop( name, localaddr, sizeof localaddr );
  return 0; 
}



extern void net_close(void)
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


extern int net_waitfd(void)
{
  return recvsock;
}


extern int* net_saved_pings(int at)
{
  return host[at].saved;
}


static void net_save_increment(void)
{
  int at;
  for (at = 0; at < MaxHost; at++) {
    memmove(host[at].saved, host[at].saved+1, (SAVED_PINGS-1)*sizeof(int));
    host[at].saved[SAVED_PINGS-1] = -2;
    host[at].saved_seq_offset += 1;
  }
}


extern void net_save_xmit(int at)
{
  if (host[at].saved[SAVED_PINGS-1] != -2) 
    net_save_increment();
  host[at].saved[SAVED_PINGS-1] = -1;
}


extern void net_save_return(int at, int seq, int ms)
{
  int idx;
  idx = seq - host[at].saved_seq_offset;
  if (idx < 0 || idx >= SAVED_PINGS) {
    return;
  }
  host[at].saved[idx] = ms;
}

/* Similar to inet_ntop but uses a sockaddr as it's argument. */
static void sockaddrtop( struct sockaddr * saddr, char * strptr, size_t len ) {
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
    error(0, 0, "sockaddrtop unknown address type");
    strptr[0] = '\0';
    return;
  }
}

/* Address comparison. */
extern int addrcmp( char * a, char * b, int family ) {
  int rc = -1;

  switch ( family ) {
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
extern void addrcpy( char * a, char * b, int family ) {

  switch ( family ) {
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
static void decodempls(int num, char *packet, struct mplslen *mpls, int offset) {

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
extern void net_add_fds(fd_set *writefd, int *maxfd)
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
extern void net_process_fds(struct mtr_ctl *ctl, fd_set *writefd)
{
  int at, fd, r;
  struct timeval now;

  /* Can't do MPLS decoding */
  struct mplslen mpls;
  mpls.labels = 0;

  gettimeofday(&now, NULL);

  for (at = 0; at < MaxSequence; at++) {
    fd = sequence[at].socket;
    if (fd > 0 && FD_ISSET(fd, writefd)) {
      r = write(fd, "G", 1);
      /* if write was successful, or connection refused we have
       * (probably) reached the remote address. Anything else happens to the
       * connection, we write it off to avoid leaking sockets */
      if (r == 1 || errno == ECONNREFUSED)
        net_process_ping(ctl, at, mpls, remoteaddress, now);
      else if (errno != EAGAIN) {
        close(fd);
        sequence[at].socket = 0;
      }
    }
    if (fd > 0) {
     struct timeval subtract;
     timersub(&now, &sequence[at].time, &subtract);
     if ((subtract.tv_sec * 1000000L + subtract.tv_usec) > ctl->tcp_timeout) {
        close(fd);
        sequence[at].socket = 0;
      }
    }
  }
}

/* for GTK frontend */
extern void net_harvest_fds(struct mtr_ctl *ctl)
{
  fd_set writefd;
  int maxfd = 0;
  struct timeval tv;

  FD_ZERO(&writefd);
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  net_add_fds(&writefd, &maxfd);
  select(maxfd, NULL, &writefd, NULL, &tv);
  net_process_fds(ctl, &writefd);
}
