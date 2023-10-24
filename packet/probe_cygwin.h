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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef PROBE_CYGWIN_H
#define PROBE_CYGWIN_H

#include <cygwin/in6.h>
typedef struct in6_addr IN6_ADDR, *PIN6_ADDR, *LPIN6_ADDR;

#include <arpa/inet.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

/*
	Windows requires an echo reply structure for each in-flight
	ICMP probe.
*/
struct probe_platform_t {
    /*
       We need a backpointer to the net_state because of the way
       IcmpSendEcho2 passes our context.
     */
    struct net_state_t *net_state;

    /*  IP version (4 or 6) used for the probe  */
    int ip_version;
};

/*  A Windows HANDLE for the ICMP session  */
struct net_state_platform_t {
    HANDLE icmp4;
    HANDLE icmp6;
    bool ip4_socket_raw;
    bool ip6_socket_raw;

    int thread_in_pipe_read, thread_in_pipe_write;
    int thread_out_pipe_read, thread_out_pipe_write;

    CRITICAL_SECTION pending_request_cs;

    /*  Guarded by the critical section.  */
    unsigned int pending_request_count;

    /*  Set when any requests are pending.  */
    HANDLE pending_request_event;
};

/*
    A request object passed between the main thread and the ICMP
    service thread representing an outstanding probe.
*/
struct icmp_thread_request_t {
    /*
        net_state and probe are const to avoid race conditions between
        the main thread and the ICMP service thread.  They are to be
        considered read-only on the ICMP service thread.
    */
    const struct net_state_t *net_state;
    const struct probe_t *probe;

    /*  Parameters for the probe request  */
    int ip_version;
    int ttl;
    int timeout;
    int packet_size;
    int bit_pattern;

    /*  Source and destination for the probe  */
    struct sockaddr_storage dest_sockaddr;
    struct sockaddr_storage src_sockaddr;

    /*  Scratch space used by the ICMP.DLL API  */
    union {
        ICMP_ECHO_REPLY *reply4;
        ICMPV6_ECHO_REPLY *reply6;
    };

    /*  Probe results  */
    int icmp_type;
    int reply_status;
    int round_trip_us;

    /*  The remote address responding to the probe  */
    struct sockaddr_storage remote_addr;
};

#endif
