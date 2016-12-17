/*
    mtr  --  a network diagnostic tool
    Copyright (C) 2016  Matt Kimball

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

#ifndef PROBE_H
#define PROBE_H

#include "platform.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/time.h>

#ifdef PLATFORM_CYGWIN
#include "probe_cygwin.h"
#else
#include "probe_unix.h"
#endif

#define MAX_PROBES 1024

/*  Use the "jumbo" frame size as the max packet size  */
#define PACKET_BUFFER_SIZE 9000

/*  Parameters for sending a new probe  */
struct probe_param_t
{
    /*  The version of the Internet Protocol to use.  (4 or 6)  */
    int ip_version;

    /*  The command token used to identify a probe when it is completed  */
    int command_token;

    /*  The IP address to probe  */
    const char *address;

    /*  Protocol for the probe, using the IPPROTO_* defines  */
    int protocol;

    /*  The destination port for non-ICMP probes  */
    int dest_port;

    /*  The "type of service" field in the IP header  */
    int type_of_service;

    /*  The packet "mark" used for mark-based routing on Linux  */
    int routing_mark;

    /*  Time to live for the transmited probe  */
    int ttl;

    /*  The packet size (in bytes) including protocol headers  */
    int packet_size;

    /*  The value with which to fill the bytes of the packet.  */
    int bit_pattern;

    /*  The number of seconds to wait before assuming the probe was lost  */
    int timeout;
};

/*  Tracking information for an outstanding probe  */
struct probe_t
{
    /*  true if this entry is in use  */
    bool used;

    /*  Command token of the probe request  */
    int token;

    /*  Platform specific probe tracking  */
    struct probe_platform_t platform;
};

/*  Global state for interacting with the network  */
struct net_state_t
{
    /*  Tracking information for in-flight probes  */
    struct probe_t probes[MAX_PROBES];

    /*  Platform specific tracking information  */
    struct net_state_platform_t platform;
};

void init_net_state_privileged(
    struct net_state_t *net_state);

void init_net_state(
    struct net_state_t *net_state);

bool is_protocol_supported(
    struct net_state_t *net_state,
    int protocol);

bool get_next_probe_timeout(
    const struct net_state_t *net_state,
    struct timeval *timeout);

void send_probe(
    struct net_state_t *net_state,
    const struct probe_param_t *param);

void receive_replies(
    struct net_state_t *net_state);

void check_probe_timeouts(
    struct net_state_t *net_state);

void respond_to_probe(
    struct probe_t *probe,
    int icmp_type,
    const struct sockaddr_storage *remote_addr,
    unsigned int round_trip_us);

int decode_dest_addr(
    const struct probe_param_t *param,
    struct sockaddr_storage *dest_sockaddr);

struct probe_t *alloc_probe(
    struct net_state_t *net_state,
    int token);

void platform_free_probe(
    struct probe_t *probe);

void free_probe(
    struct probe_t *probe);

int count_in_flight_probes(
    struct net_state_t *net_state);

struct probe_t *find_probe(
    struct net_state_t *net_state,
    int protocol,
    int icmp_id,
    int icmp_sequence);

int find_source_addr(
    struct sockaddr_storage *srcaddr,
    const struct sockaddr_storage *destaddr);

#endif
