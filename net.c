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
# include <sys/xti.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <assert.h>
#include <memory.h>
#include <unistd.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_ERROR_H
# include <error.h>
#else
# include "portability/error.h"
#endif
#ifdef HAVE_LINUX_ICMP_H
# include <linux/icmp.h>
#endif

#include "mtr.h"
#include "net.h"
#include "display.h"
#include "dns.h"
#include "utils.h"
#include "packet/cmdparse.h"

#define MinSequence 33000
#define MaxSequence 65536

#define PACKET_REPLY_BUFFER_SIZE 4096

static int packetsize;         /* packet size used by ping */

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


/*  We use a pipe to the mtr-packet subprocess to generate probes  */
struct packet_command_pipe_t {
  /*  the process id of mtr-packet  */
  pid_t pid;

  /*  the end of the pipe we read for replies  */
  int read_fd;

  /*  the end of the pipe we write for commands  */
  int write_fd;

  /* storage for incoming replies */
  char reply_buffer[PACKET_REPLY_BUFFER_SIZE];

  /*  the number of bytes currently used in reply_buffer  */
  size_t reply_buffer_used;
};


static struct nethost host[MaxHost];
static struct sequence sequence[MaxSequence];
static struct packet_command_pipe_t packet_command_pipe;

#ifdef ENABLE_IPV6
static struct sockaddr_storage sourcesockaddr_struct;
static struct sockaddr_storage remotesockaddr_struct;
static struct sockaddr_in6 * ssa6 = (struct sockaddr_in6 *) &sourcesockaddr_struct;
static struct sockaddr_in6 * rsa6 = (struct sockaddr_in6 *) &remotesockaddr_struct;
#else
static struct sockaddr_in sourcesockaddr_struct;
static struct sockaddr_in remotesockaddr_struct;
#endif

static struct sockaddr * remotesockaddr = (struct sockaddr *) &remotesockaddr_struct;
static struct sockaddr_in * ssa4 = (struct sockaddr_in *) &sourcesockaddr_struct;
static struct sockaddr_in * rsa4 = (struct sockaddr_in *) &remotesockaddr_struct;

static ip_t * sourceaddress;
static ip_t * remoteaddress;

#ifdef ENABLE_IPV6
static char localaddr[INET6_ADDRSTRLEN];
#else
# ifndef INET_ADDRSTRLEN
#  define INET_ADDRSTRLEN 16
# endif
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

/*  Attempt to find the host at a particular number of hops away  */
static void net_send_query(struct mtr_ctl *ctl, int index)
{
  int seq = new_sequence(ctl, index);
  int time_to_live = index + 1;
  char ip_string[INET6_ADDRSTRLEN];
  const char *ip_type;

  /*  Conver the remote IP address to a string  */
  if (inet_ntop(
      ctl->af, remoteaddress, ip_string, INET6_ADDRSTRLEN) == NULL) {

    display_close(ctl);
    error(EXIT_FAILURE, errno, "failure stringifying remote IP address");
  }

  if (ctl->af == AF_INET6) {
    ip_type = "ip-6";
  } else {
    ip_type = "ip-4";
  }

  /*  Send a probe using the mtr-packet subprocess  */
  if (dprintf(
    packet_command_pipe.write_fd,
    "%d send-probe %s %s ttl %d\n",
    seq, ip_type, ip_string, time_to_live) < 0) {

    display_close(ctl);
    error(EXIT_FAILURE, errno, "mtr-packet command pipe write failure");
  }
}


/*   We got a return on something we sent out.  Record the address and
     time.  */
static void net_process_ping(struct mtr_ctl *ctl, int seq, struct mplslen mpls,
			     void *addr, int totusec)
{
  int index;
  int oldavg;	/* usedByMin */
  int oldjavg;	/* usedByMin */
  int i;	/* usedByMin */
#ifdef ENABLE_IPV6
  char addrcopy[sizeof(struct in6_addr)];
#else
  char addrcopy[sizeof(struct in_addr)];
#endif

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


/*
  Extract the IP address and round trip time from a reply to a probe.
  Returns true if both arguments are found in the reply, false otherwise.
*/
static bool parse_reply_arguments(
  struct mtr_ctl *ctl, struct command_t *reply,
  ip_t *fromaddress, int *round_trip_time)
{
  bool found_round_trip;
  bool found_ip;
  char *arg_name;
  char *arg_value;
  int i;

  *round_trip_time = 0;
  memset(fromaddress, 0, sizeof(ip_t));

  found_ip = false;
  found_round_trip = false;

  /*  Examine the reply arguments for known values  */
  for (i = 0; i < reply->argument_count; i++) {
    arg_name = reply->argument_name[i];
    arg_value = reply->argument_value[i];

    if (ctl->af == AF_INET6) {
      /*  IPv6 address of the responding host  */
      if (!strcmp(arg_name, "ip-6")) {
        if (inet_pton(AF_INET6, arg_value, fromaddress)) {
          found_ip = true;
        }
      }
    } else {
      /*  IPv4 address of the responding host  */
      if (!strcmp(arg_name, "ip-4")) {
        if (inet_pton(AF_INET, arg_value, fromaddress)) {
          found_ip = true;
        }
      }
    }

    /*  The round trip time in microseconds  */
    if (!strcmp(arg_name, "round-trip-time")) {
      errno = 0;
      *round_trip_time = strtol(arg_value, NULL, 10);
      if (!errno) {
        found_round_trip = true;
      }
    }
  }

  return found_ip && found_round_trip;
}


/*
    If an mtr-packet command has returned an error result,
    report the error and exit.
*/
static void net_handle_command_reply_errors(
  struct mtr_ctl *ctl, struct command_t *reply)
{
  char *reply_name;

  reply_name = reply->command_name;

  if (!strcmp(reply_name, "no-route")) {
    display_close(ctl);
    error(EXIT_FAILURE, 0, "No route to host");
  }

  if (!strcmp(reply_name, "network-down")) {
    display_close(ctl);
    error(EXIT_FAILURE, 0, "Network down");
  }

  if (!strcmp(reply_name, "probes-exhausted")) {
    display_close(ctl);
    error(EXIT_FAILURE, 0, "Probes exhausted");
  }

  if (!strcmp(reply_name, "invalid-argument")) {
    display_close(ctl);
    error(EXIT_FAILURE, 0, "mtr-packet reported invalid argument");
  }
}


/*
    A complete mtr-packet reply line has arrived.  Parse it and record
    the responding IP and round trip time, if it is a reply that we
    understand.
*/
static void net_process_command_reply(
  struct mtr_ctl *ctl, char *reply_str)
{
  struct command_t reply;
  ip_t fromaddress;
  int seq_num;
  int round_trip_time;
  char *reply_name;
  struct mplslen mpls;

  /*  Parse the reply string  */
  if (parse_command(&reply, reply_str)) {
    /*
        If the reply isn't well structured, something is fundamentally
        wrong, as we might as well exit.  Even if the reply is of an
        unknown type, it should still parse.
    */
    display_close(ctl);
    error(EXIT_FAILURE, errno, "reply parse failure");
    return;
  }

  net_handle_command_reply_errors(ctl, &reply);

  seq_num = reply.token;
  reply_name = reply.command_name;

  /*  If the reply type is unknown, ignore it for future compatibility  */
  if (strcmp(reply_name, "reply") && strcmp(reply_name, "ttl-expired")) {
    return;
  }

  /*
      If the reply had an IP address and a round trip time, we can
      record the result.
  */
  if (parse_reply_arguments(ctl, &reply, &fromaddress, &round_trip_time)) {
    /* MPLS decoding */
    memset(&mpls, 0, sizeof(struct mplslen));
    mpls.labels = 0;

    net_process_ping(
      ctl, seq_num, mpls, (void *) &fromaddress, round_trip_time);
  }
}


/*
  Check the command pipe for completed replies to commands
  we have previously sent.  Record the results of those replies.
*/
static void net_process_pipe_buffer(struct mtr_ctl *ctl)
{
  char *reply_buffer;
  char *reply_start;
  char *end_of_reply;
  int used_size;
  int move_size;

  reply_buffer = packet_command_pipe.reply_buffer;

  /*  Terminate the string storing the replies  */
  assert(packet_command_pipe.reply_buffer_used < PACKET_REPLY_BUFFER_SIZE);
  reply_buffer[packet_command_pipe.reply_buffer_used] = 0;

  reply_start = reply_buffer;

  /*
    We may have multiple completed replies.  Loop until we don't
    have any more newlines termininating replies.
  */
  while (true) {
    /*  If no newline is found, our reply isn't yet complete  */
    end_of_reply = index(reply_start, '\n');
    if (end_of_reply == NULL) {
      /*  No complete replies remaining  */
      break;
    }

    /*
        Terminate the reply string at the newline, which
        is necessary in the case where we are able to read
        mulitple replies arriving simultaneously.
    */
    *end_of_reply = 0;

    /*  Parse and record the reply results  */
    net_process_command_reply(ctl, reply_start);

    reply_start = end_of_reply + 1;
  }

  /*
      After replies have been processed, free the space used
      by the replies, and move any remaining partial reply text
      to the start of the reply buffer.
  */
  used_size = reply_start - reply_buffer;
  move_size = packet_command_pipe.reply_buffer_used - used_size;
  memmove(reply_buffer, reply_start, move_size);
  packet_command_pipe.reply_buffer_used -= used_size;

  if (packet_command_pipe.reply_buffer_used >= 
      PACKET_REPLY_BUFFER_SIZE - 1) {
    /*
      We've overflowed the reply buffer without a complete reply.
      There's not much we can do about it but discard the data
      we've got and hope new data coming in fits.
    */
    packet_command_pipe.reply_buffer_used = 0;
  }
}


/*
    Invoked when the read pipe from the mtr-packet subprocess is readable.
    If we have received a complete reply, process it.
*/
extern void net_process_return(struct mtr_ctl *ctl)
{
  int read_count;
  int buffer_remaining;
  char *reply_buffer;
  char *read_buffer;

  reply_buffer = packet_command_pipe.reply_buffer;

  /*
      Read the available reply text, up to the the remaining
      buffer space.  (Minus one for the terminating NUL.)
  */
  read_buffer = &reply_buffer[packet_command_pipe.reply_buffer_used];
  buffer_remaining =
    PACKET_REPLY_BUFFER_SIZE - packet_command_pipe.reply_buffer_used;
  read_count = read(
    packet_command_pipe.read_fd, read_buffer, buffer_remaining - 1);

  if (read_count < 0) {
    /*
        EAGAIN simply indicates that there is no data currently
        available on our non-blocking pipe.
    */
    if (errno == EAGAIN) {
      return;
    }

    display_close(ctl);
    error(EXIT_FAILURE, errno, "command reply read failure");
    return;
  }

  if (read_count == 0) {
    display_close(ctl);

    errno = EPIPE;
    error(EXIT_FAILURE, EPIPE, "unexpected packet generator exit");
  }

  packet_command_pipe.reply_buffer_used += read_count;

  /*  Handle any replies completed by this read  */
  net_process_pipe_buffer(ctl);
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
                    (void *) remoteaddress, ctl->af ) == 0 ))
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


/*  Set a file descriptor to non-blocking  */
static void set_fd_nonblock(int fd)
{
  int flags;

  /*  Get the current flags of the file descriptor  */
  flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    error(EXIT_FAILURE, errno, "F_GETFL failure");
    exit(1);
  }

  /*  Add the O_NONBLOCK bit to the current flags  */
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    error(EXIT_FAILURE, errno, "Failure to set O_NONBLOCK");
    exit(1);
  }
}


/*  Ensure we can communicate with the mtr-packet subprocess  */
static int net_command_pipe_check(struct mtr_ctl *ctl)
{
  const char *check_command = "1 check-support feature send-probe\n";
  struct command_t command;
  char reply[PACKET_REPLY_BUFFER_SIZE];
  int command_length;
  int write_length;
  int read_length;
  int parse_result;

  /*  Query send-probe support  */
  command_length = strlen(check_command);
  write_length = write(
    packet_command_pipe.write_fd, check_command, command_length);

  if (write_length == -1) {
    return -1;
  }

  if (write_length != command_length) {
    errno = EIO;
    return -1;
  }

  /*  Read the reply to our query  */
  read_length = read(
    packet_command_pipe.read_fd, reply, PACKET_REPLY_BUFFER_SIZE - 1);

  if (read_length < 0) {
    return -1;
  }

  /*  Parse the query reply  */
  reply[read_length] = 0;
  parse_result = parse_command(&command, reply);
  if (parse_result) {
    errno = parse_result;
    return -1;
  }

  /*  Check that send-probe is supported  */
  if (!strcmp(command.command_name, "feature-support")
    && command.argument_count >= 1
    && !strcmp(command.argument_name[0], "support")
    && !strcmp(command.argument_value[0], "ok")) {

    /*  Looks good  */
    return 0;
  }

  errno = ENOTSUP;
  return -1;
}


/*  Create the command pipe to a new mtr-packet subprocess  */
static int net_command_pipe_open(struct mtr_ctl *ctl)
{
  int stdin_pipe[2];
  int stdout_pipe[2];
  pid_t child_pid;
  int i;
  char *mtr_packet_path;

  /*
      We actually need two Unix pipes.  One for stdin and one for
      stdout on the new process.
  */
  if (pipe(stdin_pipe) || pipe(stdout_pipe)) {
    return errno;
  }

  child_pid = fork();
  if (child_pid == -1) {
    return errno;
  }

  if (child_pid == 0) {
    /*  In the child process, attach our created pipes to stdin and stdout  */
    dup2(stdin_pipe[0], STDIN_FILENO);
    dup2(stdout_pipe[1], STDOUT_FILENO);

    /*  Close all unnecessary fds  */
    for (i = STDERR_FILENO + 1; i <= stdout_pipe[1]; i++) {
      close(i);
    }

    /*
        Allow the MTR_PACKET environment variable to overrride
        the path to the mtr-packet executable.  This is necessary
        for debugging changes for mtr-packet.
    */
    mtr_packet_path = getenv("MTR_PACKET");
    if (mtr_packet_path == NULL) {
      mtr_packet_path = "mtr-packet";
    }

    /*
        First, try to execute using /usr/bin/env, because this
        will search the PATH for mtr-packet
    */
    execl("/usr/bin/env", "mtr-packet", mtr_packet_path, NULL);

    /*
        If env fails to execute, try to use the MTR_PACKET environment as a
        full path to the executable.  This is necessary because on
        Windows, minimal mtr binary distributions will lack /usr/bin/env.

        Note: A side effect is that an mtr-packet in the current directory
        could be executed.  This will only be the case if /usr/bin/env
        doesn't exist.
    */
    execl(mtr_packet_path, "mtr-packet", NULL);

    /*  Both exec attempts failed, so nothing to do but exit  */
    exit(1);
  } else {
    memset(&packet_command_pipe, 0, sizeof(struct packet_command_pipe_t));

    /*
        In the parent process, save the opposite ends of the pipes
        attached as stdin and stdout in the child.
    */
    packet_command_pipe.pid = child_pid;
    packet_command_pipe.read_fd = stdout_pipe[0];
    packet_command_pipe.write_fd = stdin_pipe[1];

    /*  We don't need the child ends of the pipe open in the parent.  */
    close(stdout_pipe[1]);
    close(stdin_pipe[0]);

    /*
      Check that we can communicate with the client.  If we failed to
      execute the mtr-packet binary, we will discover that here.
    */
    if (net_command_pipe_check(ctl)) {
      error(EXIT_FAILURE, errno, "Failure to start mtr-packet");
    }

    /*  We will need non-blocking reads from the child  */
    set_fd_nonblock(packet_command_pipe.read_fd);
  }

  return 0;
}


extern int net_open(struct mtr_ctl *ctl, struct hostent * hostent)
{
  int err;

  /*  Spawn the mtr-packet child process  */
  err = net_command_pipe_open(ctl);
  if (err) {
    return err;
  }

  net_reset(ctl);

  remotesockaddr->sa_family = hostent->h_addrtype;

  switch ( hostent->h_addrtype ) {
  case AF_INET:
    addrcpy( (void *) &(rsa4->sin_addr), hostent->h_addr, AF_INET );
    sourceaddress = (ip_t *) &(ssa4->sin_addr);
    remoteaddress = (ip_t *) &(rsa4->sin_addr);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    addrcpy( (void *) &(rsa6->sin6_addr), hostent->h_addr, AF_INET6 );
    sourceaddress = (ip_t *) &(ssa6->sin6_addr);
    remoteaddress = (ip_t *) &(rsa6->sin6_addr);
    break;
#endif
  default:
    error(EXIT_FAILURE, 0, "net_open bad address type");
  }

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
  static struct nethost template = {
    .saved_seq_offset = 2 - SAVED_PINGS
  };

  int at, i;

  batch_at = ctl->fstTTL - 1;	/* above replacedByMin */
  numhosts = 10;

  for (i = 0; i < SAVED_PINGS; i++)
    template.saved[i] = -2;

  for (at = 0; at < MaxHost; at++) {
    memcpy(&(host[at]), &template, sizeof(template));
  }

  for (at = 0; at < MaxSequence; at++) {
    sequence[at].transit = 0;
    if (sequence[at].socket > 0) {
      close(sequence[at].socket);
      sequence[at].socket = 0;
    }
  }

}


/*  Close the pipe to the packet generator process, and kill the process  */
extern void net_close(void)
{
  int child_exit_value;

  if (packet_command_pipe.pid) {
    close(packet_command_pipe.read_fd);
    close(packet_command_pipe.write_fd);

    kill(packet_command_pipe.pid, SIGTERM);
    waitpid(packet_command_pipe.pid, &child_exit_value, 0);
  }

  memset(&packet_command_pipe, 0, sizeof(struct packet_command_pipe_t));
}


extern int net_waitfd(void)
{
  return packet_command_pipe.read_fd;
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
}
