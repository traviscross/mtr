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

/*
    Non-blocking DNS portion --
    Copyright (C) 1998 by Simon Kirby <sim@neato.org>
    Released under GPL, as above.
*/

#include <config.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifdef NO_STRERROR
extern int sys_nerr;
extern char *sys_errlist[];
#define strerror(errno) (((errno) >= 0 && (errno) < sys_nerr) ? sys_errlist[errno] : "unlisted error")
#endif

/*  Hmm, it seems Irix requires this  */
extern int errno;

/* Defines */

#undef Debug

#undef CorruptCheck
#undef WipeFrees
#undef WipeMallocs

#define BashSize 8192			/* Size of hash tables */
#define BashModulo(x) ((x) & 8191)	/* Modulo for hash table size: */
#define HostnameLength 255		/* From RFC */
#define ResRetryDelay1 3
#define ResRetryDelay2 4
#define ResRetryDelay3 5

/* Macros */

#define nonull(s) (s) ? s : nullstring

/* Typedefs */

typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned long dword;

typedef unsigned int ip_t;

/* Structures */

struct resolve {
   struct resolve *next;
   struct resolve *previous;
   struct resolve *nextid;
   struct resolve *previousid;
   struct resolve *nextip;
   struct resolve *previousip;
   struct resolve *nexthost;
   struct resolve *previoushost;
   char *hostname;
   double expiretime;
   ip_t ip;
   word id;
   byte state;
};

/* Non-blocking nameserver interface routines */

#define MaxPacketsize (PACKETSZ)
#define DomainLength (MAXDNAME)

#define OpcodeCount 3
char *opcodes[OpcodeCount+1] = {
   "standard query",
   "inverse query",
   "server status request",
   "unknown",
};

#define ResponsecodeCount 6
char *responsecodes[ResponsecodeCount+1] = {
   "no error",
   "format error in query",
   "server failure",
   "queried domain name does not exist",
   "requested query type not implemented",
   "refused by name server",
   "unknown error",
};

#define ResourcetypeCount 17
char *resourcetypes[ResourcetypeCount+1] = {
   "unknown type",
   "A: host address",
   "NS: authoritative name server",
   "MD: mail destination (OBSOLETE)",
   "MF: mail forwarder (OBSOLETE)",
   "CNAME: name alias",
   "SOA: authority record",
   "MB: mailbox domain name (EXPERIMENTAL)",
   "MG: mail group member (EXPERIMENTAL)",
   "MR: mail rename domain name (EXPERIMENTAL)",
   "NULL: NULL RR (EXPERIMENTAL)",
   "WKS: well known service description",
   "PTR: domain name pointer",
   "HINFO: host information",
   "MINFO: mailbox or mail list information",
   "MX: mail exchange",
   "TXT: text string",
   "unknown type",
};

#define ClasstypeCount 5
char *classtypes[ClasstypeCount+1] = {
   "unknown class",
   "IN: the Internet",
   "CS: CSNET (OBSOLETE)",
   "CH: CHAOS",
   "HS: Hesoid [Dyer 87]",
   "unknown class"
};

char *rrtypes[] = {
   "Unknown",
   "Query",
   "Answer",
   "Authority reference",
   "Resource reference",
};

enum {
   RR_UNKNOWN,
   RR_QUERY,
   RR_ANSWER,
   RR_AUTHORITY,
   RR_RESOURCE,
};

typedef struct {
   word id;             /* Packet id */
   byte databyte_a;
      /* rd:1           recursion desired
       * tc:1           truncated message
       * aa:1           authoritive answer
       * opcode:4       purpose of message
       * qr:1           response flag
       */
   byte databyte_b;
      /* rcode:4        response code
       * unassigned:2   unassigned bits
       * pr:1           primary server required (non standard)
       * ra:1           recursion available
       */
   word qdcount;        /* Query record count */
   word ancount;        /* Answer record count */
   word nscount;        /* Authority reference record count */
   word arcount;        /* Resource reference record count */
} packetheader;

#ifndef HFIXEDSZ
#define HFIXEDSZ (sizeof(packetheader))
#endif

/*
 * Byte order independent macros for packetheader
 */
#define getheader_rd(x) (x->databyte_a & 1)
#define getheader_tc(x) ((x->databyte_a >> 1) & 1)
#define getheader_aa(x) ((x->databyte_a >> 2) & 1)
#define getheader_opcode(x) ((x->databyte_a >> 3) & 15)
#define getheader_qr(x) (x->databyte_a >> 7)
#define getheader_rcode(x) (x->databyte_b & 15)
#define getheader_pr(x) ((x->databyte_b >> 6) & 1)
#define getheader_ra(x) (x->databyte_b >> 7)

#define sucknetword(x) (((word)*(x) << 8) | (((x)+= 2)[-1]))
#define sucknetshort(x) (((short)*(x) << 8) | (((x)+= 2)[-1]))
#define sucknetdword(x) (((dword)*(x) << 24) | ((x)[1] << 16) | ((x)[2] << 8) | (((x)+= 4)[-1]))
#define sucknetlong(x) (((long)*(x) << 24) | ((x)[1] << 16) | ((x)[2] << 8) | (((x)+= 4)[-1]))

enum {
   STATE_FINISHED,
   STATE_FAILED,
   STATE_PTRREQ1,
   STATE_PTRREQ2,
   STATE_PTRREQ3,
};

#define Is_PTR(x) ((x->state == STATE_PTRREQ1) || (x->state == STATE_PTRREQ2) || (x->state == STATE_PTRREQ3))

dword resrecvbuf[(MaxPacketsize + 7) >> 2]; /* MUST BE DWORD ALIGNED */

struct resolve *idbash[BashSize];
struct resolve *ipbash[BashSize];
struct resolve *hostbash[BashSize];
struct resolve *expireresolves = NULL;
struct resolve *lastresolve = NULL;
struct logline *streamlog = NULL;
struct logline *lastlog = NULL;

ip_t alignedip;
ip_t localhost;

double sweeptime;

#ifdef Debug
int debug = 1;
#else
int debug = 0;
#endif

dword mem = 0;

dword res_iplookupsuccess = 0;
dword res_reversesuccess = 0;
dword res_nxdomain = 0;
dword res_nserror = 0;
dword res_hostipmismatch = 0;
dword res_unknownid = 0;
dword res_resend = 0;
dword res_timeout = 0;

dword resolvecount = 0;

long idseed = 0xdeadbeef;
long aseed;

struct sockaddr_in from;

int resfd;
int fromlen = sizeof(struct sockaddr_in);

char tempstring[16384+1+1];
char sendstring[1024+1];
char namestring[1024+1];
char stackstring[1024+1];

char nullstring[] = "";

/* Code */


#ifdef CorruptCheck
#define TOT_SLACK 2
#define HEAD_SLACK 1
/* Need an entry for sparc systems here too. 
   Don't try this on Sparc for now. */
#else
#ifdef sparc
#define TOT_SLACK 2
#define HEAD_SLACK 2
#else
#define TOT_SLACK 1
#define HEAD_SLACK 1
#endif
#endif


void *statmalloc(size_t size){
   void *p;
   size_t mallocsize;
   mem+= size;
   mallocsize = size + TOT_SLACK * sizeof(dword);

   p = malloc(mallocsize);
   if (!p){
      fprintf(stderr,"malloc() of %u bytes failed: %s\n",size,strerror(errno));
      exit(-1);
   }
   *((dword *)p) = (dword)size;
#ifdef CorruptCheck
   *(byte *)((char *)p + size + sizeof(dword) + sizeof(byte) * 0) = 0xde;
   *(byte *)((char *)p + size + sizeof(dword) + sizeof(byte) * 1) = 0xad;
   *(byte *)((char *)p + size + sizeof(dword) + sizeof(byte) * 2) = 0xbe;
   *(byte *)((char *)p + size + sizeof(dword) + sizeof(byte) * 3) = 0xef;
#endif
   p = (void *)((dword *)p + HEAD_SLACK);
#ifdef WipeMallocs
   memset(p,0xf0,size);
#endif
   return p;
}

void statfree(void *p){
   if (p){
      if (*((dword *)p - HEAD_SLACK) == 0){
         fprintf(stderr,"ERROR: Attempt to free pointer twice.\n");
         *(int*)0=0;
         exit(-1);
      } else {
         if (*((dword *)p - HEAD_SLACK) > 8192){
            fprintf(stderr,"ERROR: Corrupted free() buffer. (header)\n");
            *(int*)0=0;
            exit(-1);
         }
#ifdef CorruptCheck
         if ((*(byte *)((char *)p + (*((dword *)p - 1)) + sizeof(byte) * 0) != 0xde) ||
              (*(byte *)((char *)p + (*((dword *)p - 1)) + sizeof(byte) * 1) != 0xad) ||
               (*(byte *)((char *)p + (*((dword *)p - 1)) + sizeof(byte) * 2) != 0xbe) ||
                (*(byte *)((char *)p + (*((dword *)p - 1)) + sizeof(byte) * 3) != 0xef)){
            fprintf(stderr,"ERROR: Corrupted free() buffer. (footer)\n");
            *(int*)0=0;
            exit(-1);
         }
#endif
         mem-= *((dword *)p - HEAD_SLACK);
#ifdef WipeFrees
         memset(p,0xfe,*((dword *)p - HEAD_SLACK));
         *((dword *)p - 1) = 0;
#endif
         free((dword *)p - HEAD_SLACK);
      }
   }
}

char *strtdiff(char *d,long signeddiff){
   dword diff;
   dword seconds,minutes,hours;
   long days;
   if ((diff = labs(signeddiff))){
      seconds = diff % 60; diff/= 60;
      minutes = diff % 60; diff/= 60;
      hours = diff % 24;
      days = signeddiff / (60 * 60 * 24);
      if (days)
         sprintf(d,"%lid",days);
      else
         *d = '\0';
      if (hours)
         sprintf(d + strlen(d),"%luh",hours);
      if (minutes)
         sprintf(d + strlen(d),"%lum",minutes);
      if (seconds)
         sprintf(d + strlen(d),"%lus",seconds);
   } else
      sprintf(d,"0s");
   return d;
}

int issetfd(fd_set *set,int fd){
   return (int)((FD_ISSET(fd,set)) && 1);
}

void setfd(fd_set *set,int fd){
   FD_SET(fd,set);
}

void clearfd(fd_set *set,int fd){
   FD_CLR(fd,set);
}

void clearset(fd_set *set){
   FD_ZERO(set);
}

char *strlongip(ip_t ip){
   struct in_addr a;
   a.s_addr = ip;
   return inet_ntoa(a);
}

ip_t longipstr(char *s){
   return inet_addr(s);
}

int dns_forward(char *name){
   struct hostent *host;
   if ((host = gethostbyname(name)))
      return *(int *)host->h_addr;
   else
      return 0;
}

int dns_waitfd(){
   return resfd;
}

void dns_open(){
   int option,i;
   res_init();
   if (!_res.nscount){
      fprintf(stderr,"No nameservers defined.\n");
      exit(-1);
   }
   _res.options|= RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
   for (i = 0;i < _res.nscount;i++)
      _res.nsaddr_list[i].sin_family = AF_INET;
   resfd = socket(AF_INET, SOCK_DGRAM, 0);
   if (resfd == -1){
      fprintf(stderr,"Unable to allocate socket for nameserver communication: %s\n",
       strerror(errno));
      exit(-1);
   }
   option = 1;
   if (setsockopt(resfd,SOL_SOCKET,SO_BROADCAST,(char *)&option,sizeof(option))){
      fprintf(stderr,"Unable to setsockopt() on nameserver communication socket: %s\n",
       strerror(errno));
      exit(-1);
   }
   localhost = longipstr("127.0.0.1");
   aseed = time(NULL) ^ (time(NULL) << 3) ^ (dword)getpid();
   for (i = 0;i < BashSize;i++){
      idbash[i] = NULL;
      hostbash[i] = NULL;
   }
}

struct resolve *allocresolve(){
   struct resolve *rp;
   rp = (struct resolve *)statmalloc(sizeof(struct resolve));
   if (!rp){
      fprintf(stderr,"statmalloc() failed: %s\n",strerror(errno));
      exit(-1);
   }
   memset(rp,0, sizeof(struct resolve));
   return rp;
}

dword getidbash(word id){
   return (dword)BashModulo(id);
}

dword getipbash(ip_t ip){
   return (dword)BashModulo(ip);
}

dword gethostbash(char *host){
   dword bashvalue = 0;
   for (;*host;host++){
      bashvalue^= *host;
      bashvalue+= (*host >> 1) + (bashvalue >> 1);
   }
   return BashModulo(bashvalue);
}

void linkresolveid(struct resolve *addrp){
   struct resolve *rp;
   dword bashnum;
   bashnum = getidbash(addrp->id);
   rp = idbash[bashnum];
   if (rp){
      while ((rp->nextid) && (addrp->id > rp->nextid->id))
         rp = rp->nextid;
      while ((rp->previousid) && (addrp->id < rp->previousid->id))
         rp = rp->previousid;
      if (rp->id < addrp->id){
         addrp->previousid = rp;
         addrp->nextid = rp->nextid;
         if (rp->nextid)
            rp->nextid->previousid = addrp;
         rp->nextid = addrp;
      } else {
         addrp->previousid = rp->previousid;
         addrp->nextid = rp;
         if (rp->previousid)
            rp->previousid->nextid = addrp;
         rp->previousid = addrp;
      }
   } else
      addrp->nextid = addrp->previousid = NULL;
   idbash[bashnum] = addrp;
}

void unlinkresolveid(struct resolve *rp){
   dword bashnum;
   bashnum = getidbash(rp->id);
   if (idbash[bashnum] == rp)
      if (rp->previousid)
         idbash[bashnum] = rp->previousid;
      else
         idbash[bashnum] = rp->nextid;
   if (rp->nextid)
      rp->nextid->previousid = rp->previousid;
   if (rp->previousid)
      rp->previousid->nextid = rp->nextid;
}

void linkresolvehost(struct resolve *addrp){
   struct resolve *rp;
   dword bashnum;
   bashnum = gethostbash(addrp->hostname);
   rp = hostbash[bashnum];
   if (rp){
      while ((rp->nexthost) && (strcasecmp(addrp->hostname,rp->nexthost->hostname) < 0))
         rp = rp->nexthost;
      while ((rp->previoushost) && (strcasecmp(addrp->hostname,rp->previoushost->hostname) > 0))
         rp = rp->previoushost;
      if (strcasecmp(addrp->hostname,rp->hostname) < 0){
         addrp->previoushost = rp;
         addrp->nexthost = rp->nexthost;
         if (rp->nexthost)
            rp->nexthost->previoushost = addrp;
         rp->nexthost = addrp;
      } else {
         addrp->previoushost = rp->previoushost;
         addrp->nexthost = rp;
         if (rp->previoushost)
            rp->previoushost->nexthost = addrp;
         rp->previoushost = addrp;
      }
   } else
      addrp->nexthost = addrp->previoushost = NULL;
   hostbash[bashnum] = addrp;
}

void unlinkresolvehost(struct resolve *rp){
   dword bashnum;
   bashnum = gethostbash(rp->hostname);
   if (hostbash[bashnum] == rp)
      if (rp->previoushost)
         hostbash[bashnum] = rp->previoushost;
      else
         hostbash[bashnum] = rp->nexthost;
   if (rp->nexthost)
      rp->nexthost->previoushost = rp->previoushost;
   if (rp->previoushost)
      rp->previoushost->nexthost = rp->nexthost;
   statfree(rp->hostname);
}

void linkresolveip(struct resolve *addrp){
   struct resolve *rp;
   dword bashnum;
   bashnum = getipbash(addrp->ip);
   rp = ipbash[bashnum];
   if (rp){
      while ((rp->nextip) && (addrp->ip > rp->nextip->ip))
         rp = rp->nextip;
      while ((rp->previousip) && (addrp->ip < rp->previousip->ip))
         rp = rp->previousip;
      if (rp->ip < addrp->ip){
         addrp->previousip = rp;
         addrp->nextip = rp->nextip;
         if (rp->nextip)
            rp->nextip->previousip = addrp;
         rp->nextip = addrp;
      } else {
         addrp->previousip = rp->previousip;
         addrp->nextip = rp;
         if (rp->previousip)
            rp->previousip->nextip = addrp;
         rp->previousip = addrp;
      }
   } else
      addrp->nextip = addrp->previousip = NULL;
   ipbash[bashnum] = addrp;
}

void unlinkresolveip(struct resolve *rp){
   dword bashnum;
   bashnum = getipbash(rp->ip);
   if (ipbash[bashnum] == rp)
      if (rp->previousip)
         ipbash[bashnum] = rp->previousip;
      else
         ipbash[bashnum] = rp->nextip;
   if (rp->nextip)
      rp->nextip->previousip = rp->previousip;
   if (rp->previousip)
      rp->previousip->nextip = rp->nextip;
}

void linkresolve(struct resolve *rp){
   struct resolve *irp;
   if (expireresolves){
      irp = expireresolves;
      while ((irp->next) && (rp->expiretime >= irp->expiretime)) irp = irp->next;
      if (rp->expiretime >= irp->expiretime){
         rp->next = NULL;
         rp->previous = irp;
         irp->next = rp;
         lastresolve = rp;
      } else {
         rp->previous = irp->previous;
         rp->next = irp;
         if (irp->previous)
            irp->previous->next = rp;
         else
            expireresolves = rp;
         irp->previous = rp;
      }
   } else {
      rp->next = NULL;
      rp->previous = NULL;
      expireresolves = lastresolve = rp;
   }
   resolvecount++;
}

void lastlinkresolve(struct resolve *rp){
   struct resolve *irp;
   if (lastresolve){
      irp = lastresolve;
      while ((irp->previous) && (rp->expiretime < irp->expiretime)) irp = irp->previous;
      while ((irp->next) && (rp->expiretime >= irp->expiretime)) irp = irp->next;
      if (rp->expiretime >= irp->expiretime){
         rp->next = NULL;
         rp->previous = irp;
         irp->next = rp;
         lastresolve = rp;
      } else {
         rp->previous = irp->previous;
         rp->next = irp;
         if (irp->previous)
            irp->previous->next = rp;
         else
            expireresolves = rp;
         irp->previous = rp;
      }
   } else {
      rp->next = NULL;
      rp->previous = NULL;
      expireresolves = lastresolve = rp;
   }
   resolvecount++;
}

void untieresolve(struct resolve *rp){
   if (rp->previous)
      rp->previous->next = rp->next;
   else
      expireresolves = rp->next;
   if (rp->next)
      rp->next->previous = rp->previous;
   else
      lastresolve = rp->previous;
   resolvecount--;
}

void unlinkresolve(struct resolve *rp){
   untieresolve(rp);
   unlinkresolveid(rp);
   unlinkresolveip(rp);
   if (rp->hostname)
      unlinkresolvehost(rp);
}

struct resolve *findid(word id){
   struct resolve *rp;
   int bashnum;
   bashnum = getidbash(id);
   rp = idbash[bashnum];
   if (rp){
      while ((rp->nextid) && (id >= rp->nextid->id))
         rp = rp->nextid;
      while ((rp->previousid) && (id <= rp->previousid->id))
         rp = rp->previousid;
      if (id == rp->id){
         idbash[bashnum] = rp;
         return rp;
      } else
         return NULL;
   }
   return rp; /* NULL */
}

struct resolve *findhost(char *hostname){
   struct resolve *rp;
   int bashnum;
   bashnum = gethostbash(hostname);
   rp = hostbash[bashnum];
   if (rp){
      while ((rp->nexthost) && (strcasecmp(hostname,rp->nexthost->hostname) >= 0))
         rp = rp->nexthost;
      while ((rp->previoushost) && (strcasecmp(hostname,rp->nexthost->hostname) <= 0))
         rp = rp->previoushost;
      if (strcasecmp(hostname,rp->hostname))
         return NULL;
      else {
         hostbash[bashnum] = rp;
         return rp;
      }
   }
   return rp; /* NULL */
}

struct resolve *findip(ip_t ip){
   struct resolve *rp;
   dword bashnum;
   bashnum = getipbash(ip);
   rp = ipbash[bashnum];
   if (rp){
      while ((rp->nextip) && (ip >= rp->nextip->ip))
         rp = rp->nextip;
      while ((rp->previousip) && (ip <= rp->previousip->ip))
         rp = rp->previousip;
      if (ip == rp->ip){
         ipbash[bashnum] = rp;
         return rp;
      } else
         return NULL;
   }
   return rp; /* NULL */
}

void restell(char *s){
   fputs(s,stderr);
   fputs("\r",stderr);
}

void dorequest(char *s,int type,word id){
   packetheader *hp;
   int r,i;
   byte buf[MaxPacketsize+1];
   r = res_mkquery(QUERY,s,C_IN,type,NULL,0,NULL,buf,MaxPacketsize);
   if (r == -1){
      restell("Resolver error: Query too large.");
      return;
   }
   hp = (packetheader *)buf;
   hp->id = id;	/* htons() deliberately left out (redundant) */
   for (i = 0;i < _res.nscount;i++)
      (void)sendto(resfd,buf,r,0,(struct sockaddr *)&_res.nsaddr_list[i],
       sizeof(struct sockaddr));
}

void resendrequest(struct resolve *rp,int type){
   if (type == T_A){
      dorequest(rp->hostname,type,rp->id);
      if (debug){
         sprintf(tempstring,"Resolver: Sent reverse authentication request for \"%s\".",
          rp->hostname);
         restell(tempstring);
      }
   } else if (type == T_PTR){
      sprintf(tempstring,"%u.%u.%u.%u.in-addr.arpa",
       ((byte *)&rp->ip)[3],
        ((byte *)&rp->ip)[2],
         ((byte *)&rp->ip)[1],
          ((byte *)&rp->ip)[0]);
      dorequest(tempstring,type,rp->id);
      if (debug){
         sprintf(tempstring,"Resolver: Sent domain lookup request for \"%s\".",
          strlongip(rp->ip));
         restell(tempstring);
      }
   }
}

void sendrequest(struct resolve *rp,int type){
   do {
      idseed = (((idseed + idseed) | (long)time(NULL)) + idseed - 0x54bad4a) ^ aseed;
      aseed^= idseed;
      rp->id = (word)idseed;
   } while (findid(rp->id));
   linkresolveid(rp);
   resendrequest(rp,type);
}

void failrp(struct resolve *rp){
   if (rp->state == STATE_FINISHED)
      return;
   rp->state = STATE_FAILED;
   untieresolve(rp);
   if (debug)
      restell("Resolver: Lookup failed.\n");
}

void passrp(struct resolve *rp,long ttl){
   rp->state = STATE_FINISHED;
   rp->expiretime = sweeptime + (double)ttl;
   untieresolve(rp);
   if (debug){
      sprintf(tempstring,"Resolver: Lookup successful: %s\n",rp->hostname);
      restell(tempstring);
   }
}

void parserespacket(byte *s,int l){
   struct resolve *rp;
   packetheader *hp;
   byte *eob;
   byte *c;
   long ttl;
   int r,usefulanswer;
   word rr,datatype,class,qdatatype,qclass;
   byte rdatalength;
   if (l < sizeof(packetheader)){
      restell("Resolver error: Packet smaller than standard header size.");
      return;
   }
   if (l == sizeof(packetheader)){
      restell("Resolver error: Packet has empty body.");
      return;
   }
   hp = (packetheader *)s;
   /* Convert data to host byte order */
   /* hp->id does not need to be redundantly byte-order flipped, it is only echoed by nameserver */
   rp = findid(hp->id);
   if (!rp){
      res_unknownid++;
      return;
   }
   if ((rp->state == STATE_FINISHED) || (rp->state == STATE_FAILED))
      return;
   hp->qdcount = ntohs(hp->qdcount);
   hp->ancount = ntohs(hp->ancount);
   hp->nscount = ntohs(hp->nscount);
   hp->arcount = ntohs(hp->arcount);
   if (getheader_tc(hp)){ /* Packet truncated */
      restell("Resolver error: Nameserver packet truncated.");
      return;
   }
   if (!getheader_qr(hp)){ /* Not a reply */
      restell("Resolver error: Query packet received on nameserver communication socket.");
      return;
   }
   if (getheader_opcode(hp)){ /* Not opcode 0 (standard query) */
      restell("Resolver error: Invalid opcode in response packet.");
      return;
   }
   eob = s + l;
   c = s + HFIXEDSZ;
   switch (getheader_rcode(hp)){
      case NOERROR:
         if (hp->ancount){
            if (debug){
               sprintf(tempstring,"Resolver: Received nameserver reply. (qd:%u an:%u ns:%u ar:%u)",
                hp->qdcount,hp->ancount,hp->nscount,hp->arcount);
               restell(tempstring);
            }
            if (hp->qdcount != 1){
               restell("Resolver error: Reply does not contain one query.");
               return;
            }
            if (c > eob){
               restell("Resolver error: Reply too short.");
               return;
            }
            switch (rp->state){ /* Construct expected query reply */
               case STATE_PTRREQ1:
               case STATE_PTRREQ2:
               case STATE_PTRREQ3:
                  sprintf(stackstring,"%u.%u.%u.%u.in-addr.arpa",
                   ((byte *)&rp->ip)[3],
                    ((byte *)&rp->ip)[2],
                     ((byte *)&rp->ip)[1],
                      ((byte *)&rp->ip)[0]);
                  break;
            }
            *namestring = '\0';
            r = dn_expand(s,s + l,c,namestring,MAXDNAME);
            if (r == -1){
               restell("Resolver error: dn_expand() failed while expanding query domain.");
               return;
            }
            namestring[strlen(stackstring)] = '\0';
            if (strcasecmp(stackstring,namestring)){
               if (debug){
                  sprintf(tempstring,"Resolver: Unknown query packet dropped. (\"%s\" does not match \"%s\")",
                   stackstring,namestring);
                  restell(tempstring);
               }
               return;
            }
            if (debug){
               sprintf(tempstring,"Resolver: Queried domain name: \"%s\"",namestring);
               restell(tempstring);
            }
            c+= r;
            if (c + 4 > eob){
               restell("Resolver error: Query resource record truncated.");
               return;
            }
            qdatatype = sucknetword(c);
            qclass = sucknetword(c);
            if (qclass != C_IN){
               sprintf(tempstring,"Resolver error: Received unsupported query class: %u (%s)",
                qclass,qclass < ClasstypeCount ? classtypes[qclass] :
                 classtypes[ClasstypeCount]);
               restell(tempstring);
            }
            switch (qdatatype){
               case T_PTR:
                  if (!Is_PTR(rp))
                     if (debug){
                        restell("Resolver warning: Ignoring response with unexpected query type \"PTR\".");
                        return;
                     }
                  break;
               default:
                  sprintf(tempstring,"Resolver error: Received unimplemented query type: %u (%s)",
                   qdatatype,qdatatype < ResourcetypeCount ?
                    resourcetypes[qdatatype] : resourcetypes[ResourcetypeCount]);
                  restell(tempstring);
            }
            for (rr = hp->ancount + hp->nscount + hp->arcount;rr;rr--){
               if (c > eob){
                  restell("Resolver error: Packet does not contain all specified resouce records.");
                  return;
               }
               *namestring = '\0';
               r = dn_expand(s,s + l,c,namestring,MAXDNAME);
               if (r == -1){
                  restell("Resolver error: dn_expand() failed while expanding answer domain.");
                  return;
               }
               namestring[strlen(stackstring)] = '\0';
               if (strcasecmp(stackstring,namestring))
                  usefulanswer = 0;
               else
                  usefulanswer = 1;
               if (debug){
                  sprintf(tempstring,"Resolver: answered domain query: \"%s\"",namestring);
                  restell(tempstring);
               }
               c+= r;
               if (c + 10 > eob){
                  restell("Resolver error: Resource record truncated.");
                  return;
               }
               datatype = sucknetword(c);
               class = sucknetword(c);
               ttl = sucknetlong(c);
               rdatalength = sucknetword(c);
               if (class != qclass){
                  sprintf(tempstring,"query class: %u (%s)",qclass,qclass < ClasstypeCount ?
                   classtypes[qclass] : classtypes[ClasstypeCount]);
                  restell(tempstring);
                  sprintf(tempstring,"rr class: %u (%s)",class,class < ClasstypeCount ?
                   classtypes[class] : classtypes[ClasstypeCount]);
                  restell(tempstring);
                  restell("Resolver error: Answered class does not match queried class.");
                  return;
               }
               if (!rdatalength){
                  restell("Resolver error: Zero size rdata.");
                  return;
               }
               if (c + rdatalength > eob){
                  restell("Resolver error: Specified rdata length exceeds packet size.");
                  return;
               }
               if (datatype == qdatatype){
                  if (debug){
                     sprintf(tempstring,"Resolver: TTL: %s",strtdiff(sendstring,ttl));
                     restell(tempstring);
                  }
                  if (usefulanswer)
                     switch (datatype){
                        case T_A:
                           if (rdatalength != 4){
                              sprintf(tempstring,"Resolver error: Unsupported rdata format for \"A\" type. (%u bytes)",
                               rdatalength);
                              restell(tempstring);
                              return;
                           }
                           if (memcmp(&rp->ip,(ip_t *)c,sizeof(ip_t))){
                              sprintf(tempstring,"Resolver: Reverse authentication failed: %s != ",
                               strlongip(rp->ip));
                              memcpy(&alignedip,(ip_t *)c,sizeof(ip_t));
                              strcat(tempstring,strlongip(alignedip));
                              restell(tempstring);
                              res_hostipmismatch++;
                              failrp(rp);
                           } else {
                              sprintf(tempstring,"Resolver: Reverse authentication complete: %s == \"%s\".",
                               strlongip(rp->ip),nonull(rp->hostname));
                              restell(tempstring);
                              res_reversesuccess++;
                              passrp(rp,ttl);
                              return;
                           }
                           break;
                        case T_PTR:
                           *namestring = '\0';
                           r = dn_expand(s,s + l,c,namestring,MAXDNAME);
                           if (r == -1){
                              restell("Resolver error: dn_expand() failed while expanding domain in rdata.");
                              return;
                           }
                           if (debug){
                              sprintf(tempstring,"Resolver: Answered domain: \"%s\"",namestring);
                              restell(tempstring);
                           }
                           if (r > HostnameLength){
                              restell("Resolver error: Domain name too long.");
                              failrp(rp);
                              return;
                           }
                           if (!rp->hostname){
                              rp->hostname = (char *)statmalloc(strlen(namestring) + 1);
                              if (!rp->hostname){
                                 fprintf(stderr,"statmalloc() error: %s\n",strerror(errno));
                                 exit(-1);
                              }
                              strcpy(rp->hostname,namestring);
                              linkresolvehost(rp);
                              passrp(rp,ttl);
                              res_iplookupsuccess++;
                           }
                           break;
                        default:
                           sprintf(tempstring,"Resolver error: Received unimplemented data type: %u (%s)",
                            datatype,datatype < ResourcetypeCount ?
                             resourcetypes[datatype] : resourcetypes[ResourcetypeCount]);
                           restell(tempstring);
                     }
               } else {
                  if (debug){
                     sprintf(tempstring,"Resolver: Ignoring resource type %u. (%s)",
                      datatype,datatype < ResourcetypeCount ?
                       resourcetypes[datatype] : resourcetypes[ResourcetypeCount]);
                     restell(tempstring);
                  }
               }
               c+= rdatalength;
            }
         } else
            restell("Resolver error: No error returned but no answers given.");
         break;
      case NXDOMAIN:
         if (debug)
            restell("Resolver: Host not found.");
         res_nxdomain++;
         failrp(rp);
         break;
      default:
         sprintf(tempstring,"Resolver: Received error response %u. (%s)",
          getheader_rcode(hp),getheader_rcode(hp) < ResponsecodeCount ?
           responsecodes[getheader_rcode(hp)] : responsecodes[ResponsecodeCount]);
         restell(tempstring);
         res_nserror++;
   }
}

void dns_ack(){
   int r,i;
   r = recvfrom(resfd,(byte *)resrecvbuf,MaxPacketsize,0,(struct sockaddr *)&from,&fromlen);
   if (r > 0){
      /* Check to see if this server is actually one we sent to */
      if (from.sin_addr.s_addr == localhost){
         for (i = 0;i < _res.nscount;i++)
            if ((_res.nsaddr_list[i].sin_addr.s_addr == from.sin_addr.s_addr) ||
                (!_res.nsaddr_list[i].sin_addr.s_addr))	/* 0.0.0.0 replies as 127.0.0.1 */
               break;
      } else
         for (i = 0;i < _res.nscount;i++)
            if (_res.nsaddr_list[i].sin_addr.s_addr == from.sin_addr.s_addr)
               break;
      if (i == _res.nscount){
         sprintf(tempstring,"Resolver error: Received reply from unknown source: %s",
          strlongip(from.sin_addr.s_addr));
         restell(tempstring);
      } else
         parserespacket((byte *)resrecvbuf,r);
   } else {
      sprintf(tempstring,"Resolver: Socket error: %s",strerror(errno));
      restell(tempstring);
   }
}

int istime(double x,double *sinterval){
   if (x)
      if (x > sweeptime){
         if (*sinterval > x - sweeptime)
            *sinterval = x - sweeptime;
      } else
         return 1;
   return 0;
}

void dns_events(double *sinterval){
   struct resolve *rp,*nextrp;
   for (rp = expireresolves;(rp) && (sweeptime >= rp->expiretime);rp = nextrp){
      nextrp = rp->next;
      switch (rp->state){
         case STATE_FINISHED:	/* TTL has expired */
         case STATE_FAILED:	/* Fake TTL has expired */
            if (debug){
               sprintf(tempstring,"Resolver: Cache record for \"%s\" (%s) has expired. (state: %u)  Marked for expire at: %g, time: %g.",
                nonull(rp->hostname),strlongip(rp->ip),rp->state,rp->expiretime,sweeptime);
               restell(tempstring);
            }
            unlinkresolve(rp);
            break;
         case STATE_PTRREQ1:	/* First T_PTR send timed out */
            resendrequest(rp,T_PTR);
            restell("Resolver: Send #2 for \"PTR\" query...");
            rp->state++;
            rp->expiretime = sweeptime + ResRetryDelay2;
            (void)istime(rp->expiretime,sinterval);
            res_resend++;
            break;
         case STATE_PTRREQ2:	/* Second T_PTR send timed out */
            resendrequest(rp,T_PTR);
            restell("Resolver: Send #3 for \"PTR\" query...");
            rp->state++;
            rp->expiretime = sweeptime + ResRetryDelay3;
            (void)istime(rp->expiretime,sinterval);
            res_resend++;
            break;
         case STATE_PTRREQ3:	/* Third T_PTR timed out */
            restell("Resolver: \"PTR\" query timed out.");
            failrp(rp);
            (void)istime(rp->expiretime,sinterval);
            res_timeout++;
            break;
      }
   }
   if (expireresolves)
      (void)istime(expireresolves->expiretime,sinterval);
}

char *dns_lookup(ip_t ip){
   struct resolve *rp;
   ip = htonl(ip);
   if ((rp = findip(ip))){
      if ((rp->state == STATE_FINISHED) || (rp->state == STATE_FAILED)){
         if ((rp->state == STATE_FINISHED) && (rp->hostname)){
            if (debug){
               sprintf(tempstring,"Resolver: Used cached record: %s == \"%s\".\n",
                strlongip(ip),rp->hostname);
               restell(tempstring);
            }
            return rp->hostname;
         } else {
            if (debug){
               sprintf(tempstring,"Resolver: Used failed record: %s == ???\n",
                strlongip(ip));
               restell(tempstring);
            }
            return strlongip(ip);
         }
      }
      return strlongip(ip);
   }
   if (debug)
      fprintf(stderr,"Resolver: Added to new record.\n");
   rp = allocresolve();
   rp->state = STATE_PTRREQ1;
   rp->expiretime = sweeptime + ResRetryDelay1;
   rp->ip = ip;
   linkresolve(rp);
   rp->ip = ip;
   linkresolveip(rp);
   sendrequest(rp,T_PTR);
   return strlongip(ip);
}
