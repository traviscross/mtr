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

#include "probe.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "platform.h"
#include "construct_unix.h"
#include "deconstruct_unix.h"
#include "timeval.h"

/*  Use the "jumbo" frame size as the max packet size  */
#define PACKET_BUFFER_SIZE 9000

/*  Set the IPv6 options affecting and outgoing IPv6 packet  */
static
void set_ipv6_socket_options(
    int socket,
    const struct probe_param_t *param)
{
    if (setsockopt(
            socket, IPPROTO_IPV6,
            IPV6_UNICAST_HOPS, &param->ttl, sizeof(int))) {

        perror("Failure to set IPV6_UNICAST_HOPS");
        exit(1);
    }
}

/*  A wrapper around sendto for mixed IPv4 and IPv6 sending  */
static
int send_packet(
    const struct net_state_t *net_state,
    const struct probe_param_t *param,
    const char *packet,
    int packet_size,
    const struct sockaddr_storage *sockaddr)
{
    int send_socket;
    int sockaddr_length;

    if (sockaddr->ss_family == AF_INET6) {
        send_socket = net_state->platform.ipv6_send_socket;
        sockaddr_length = sizeof(struct sockaddr_in6);

        if (!net_state->platform.ipv6_header_constructed) {
            set_ipv6_socket_options(send_socket, param);
        }
    } else {
        assert(sockaddr->ss_family == AF_INET);
        send_socket = net_state->platform.ipv4_send_socket;
        sockaddr_length = sizeof(struct sockaddr_in);
    }

    return sendto(
        send_socket, packet, packet_size, 0,
        (struct sockaddr *)sockaddr, sockaddr_length);
}

/*
    Nearly all fields in the IP header should be encoded in network byte
    order prior to passing to send().  However, the required byte order of
    the length field of the IP header is inconsistent between operating
    systems and operating system versions.  FreeBSD 11 requires the length
    field in network byte order, but some older versions of FreeBSD
    require host byte order.  OS X requires the length field in host
    byte order.  Linux will accept either byte order.

    Test for a byte order which works by sending a ping to localhost.
*/
static
void check_length_order(
    struct net_state_t *net_state)
{
    char packet[PACKET_BUFFER_SIZE];
    struct probe_param_t param;
    struct sockaddr_storage dest_sockaddr;
    ssize_t bytes_sent;
    int packet_size;

    memset(&param, 0, sizeof(struct probe_param_t));
    param.ip_version = 4;
    param.ttl = 255;
    param.address = "127.0.0.1";

    if (decode_dest_addr(&param, &dest_sockaddr)) {
        fprintf(stderr, "Error decoding localhost address\n");
        exit(1);
    }

    /*  First attempt to ping the localhost with network byte order  */
    net_state->platform.ip_length_host_order = false;

    packet_size = construct_packet(
        net_state, packet, PACKET_BUFFER_SIZE, &dest_sockaddr, &param);
    if (packet_size < 0) {
        errno = -packet_size;
        perror("Unable to send to localhost");
        exit(1);
    }

    bytes_sent = send_packet(
        net_state, &param, packet, packet_size, &dest_sockaddr);
    if (bytes_sent > 0) {
        return;
    }

    /*  Since network byte order failed, try host byte order  */
    net_state->platform.ip_length_host_order = true;

    packet_size = construct_packet(
        net_state, packet, PACKET_BUFFER_SIZE, &dest_sockaddr, &param);
    if (packet_size < 0) {
        errno = -packet_size;
        perror("Unable to send to localhost");
        exit(1);
    }

    bytes_sent = send_packet(
        net_state, &param, packet, packet_size, &dest_sockaddr);
    if (bytes_sent < 0) {
        perror("Unable to send with swapped length");
        exit(1);
    }
}

/*  Set a socket to non-blocking mode  */
static
void set_socket_nonblocking(
    int socket)
{
    int flags;

    flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        perror("Unexpected socket F_GETFL error");
        exit(1);
    }

    if (fcntl(socket, F_SETFL, flags | O_NONBLOCK)) {
        perror("Unexpected socket F_SETFL O_NONBLOCK error");
        exit(1);
    }
}

/*  Open the raw sockets for sending/receiving IPv4 packets  */
static
void open_ipv4_sockets(
    struct net_state_t *net_state)
{
    int send_socket;
    int recv_socket;
    int trueopt = 1;

    send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_socket == -1) {
        perror("Failure opening IPv4 send socket");
        exit(1);
    }

    /*
        We will be including the IP header in transmitted packets.
        Linux doesn't require this, but BSD derived network stacks do.
    */
    if (setsockopt(
        send_socket, IPPROTO_IP, IP_HDRINCL, &trueopt, sizeof(int))) {

        perror("Failure to set IP_HDRINCL");
        exit(1);
    }

    /*
        Open a second socket with IPPROTO_ICMP because we are only
        interested in receiving ICMP packets, not all packets.
    */
    recv_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_socket == -1) {
        perror("Failure opening IPv4 receive socket");
        exit(1);
    }

    net_state->platform.ipv4_send_socket = send_socket;
    net_state->platform.ipv4_recv_socket = recv_socket;
}

/*  Open the raw sockets for sending/receiving IPv6 packets  */
static
void open_ipv6_sockets(
    struct net_state_t *net_state)
{
    int send_socket;
    int recv_socket;
    int send_protocol;

    /*
        Linux allows us to construct our own IPv6 header, so
        we'll prefer that method for more explicit control.

        Other OSes, such as MacOS, don't allow this, and on
        those platforms we must use setsockopt() to control
        fields of the IP header.
    */
#ifdef PLATFORM_LINUX
    net_state->platform.ipv6_header_constructed = true;
#else
    net_state->platform.ipv6_header_constructed = false;
#endif

    if (net_state->platform.ipv6_header_constructed) {
        send_protocol = IPPROTO_RAW;
    } else {
        send_protocol = IPPROTO_ICMPV6;
    }

    send_socket = socket(AF_INET6, SOCK_RAW, send_protocol);
    if (send_socket == -1) {
        perror("Failure opening IPv6 send socket");
        exit(1);
    }

    recv_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (recv_socket == -1) {
        perror("Failure opening IPv6 receive socket");
        exit(1);
    }

    set_socket_nonblocking(recv_socket);

    net_state->platform.ipv6_send_socket = send_socket;
    net_state->platform.ipv6_recv_socket = recv_socket;
}

/*
    The first half of the net state initialization.  Since this
    happens with elevated privileges, this is kept as minimal
    as possible to minimize security risk.
*/
void init_net_state_privileged(
    struct net_state_t *net_state)
{
    memset(net_state, 0, sizeof(struct net_state_t));

    open_ipv4_sockets(net_state);
    open_ipv6_sockets(net_state);
}

/*
    The second half of net state initialization, which is run
    at normal privilege levels.
*/
void init_net_state(
    struct net_state_t *net_state)
{
    set_socket_nonblocking(net_state->platform.ipv4_recv_socket);
    set_socket_nonblocking(net_state->platform.ipv6_recv_socket);

    check_length_order(net_state);
}

/*  Craft a custom ICMP packet for a network probe.  */
void send_probe(
    struct net_state_t *net_state,
    const struct probe_param_t *param)
{
    char packet[PACKET_BUFFER_SIZE];
    struct sockaddr_storage dest_sockaddr;
    struct probe_t *probe;
    int packet_size;

    if (decode_dest_addr(param, &dest_sockaddr)) {
        printf("%d invalid-argument\n", param->command_token);
        return;
    }

    packet_size = construct_packet(
        net_state, packet, PACKET_BUFFER_SIZE, &dest_sockaddr, param);
    if (packet_size < 0) {
        if (packet_size == -EINVAL) {
            printf("%d invalid-argument\n", param->command_token);
        } else if (packet_size == -ENETDOWN) {
            printf("%d network-down\n", param->command_token);
        } else if (packet_size == -ENETUNREACH) {
            printf("%d no-route\n", param->command_token);
        } else {
            errno = -packet_size;
            perror("Failure constructing packet");
            exit(1);
        }
        return;
    }

    probe = alloc_probe(net_state, param->command_token);
    if (probe == NULL) {
        printf("%d probes-exhausted\n", param->command_token);
        return;
    }

    /*
        We get the time just before the send call to keep the timing
        as tight as possible.
    */
    if (gettimeofday(&probe->platform.departure_time, NULL)) {
        perror("gettimeofday failure");
        exit(1);
    }

    if (send_packet(
            net_state, param, packet, packet_size, &dest_sockaddr) == -1) {

        perror("Failure sending probe");
        exit(1);
    }

    probe->platform.timeout_time = probe->platform.departure_time;
    probe->platform.timeout_time.tv_sec += param->timeout;
}

/*
    Read all available packets through our receiving raw socket, and
    handle any responses to probes we have preivously sent.
*/
void receive_replies_from_socket(
    struct net_state_t *net_state,
    int socket,
    received_packet_func_t handle_received_packet)
{
    char packet[PACKET_BUFFER_SIZE];
    int packet_length;
    struct sockaddr_storage remote_addr;
    socklen_t sockaddr_length;
    struct timeval timestamp;

    /*  Read until no more packets are available  */
    while (true) {
        sockaddr_length = sizeof(struct sockaddr_storage);
        packet_length = recvfrom(
            socket, packet, PACKET_BUFFER_SIZE, 0,
            (struct sockaddr *)&remote_addr, &sockaddr_length);

        /*
            Get the time immediately after reading the packet to
            keep the timing as precise as we can.
        */
        if (gettimeofday(&timestamp, NULL)) {
            perror("gettimeofday failure");
            exit(1);
        }

        if (packet_length == -1) {
            /*
                EAGAIN will be returned if there is no current packet
                available.
            */
            if (errno == EAGAIN) {
                return;
            }

            /*
                EINTER will be returned if we received a signal during
                receive.
            */
            if (errno == EINTR) {
                continue;
            }

            perror("Failure receiving replies");
            exit(1);
        }

        handle_received_packet(
            net_state, &remote_addr, packet, packet_length, timestamp);
    }

}

/*  Check both the IPv4 and IPv6 sockets for incoming packets  */
void receive_replies(
    struct net_state_t *net_state)
{
    receive_replies_from_socket(
        net_state, net_state->platform.ipv4_recv_socket,
        handle_received_ipv4_packet);

    receive_replies_from_socket(
        net_state, net_state->platform.ipv6_recv_socket,
        handle_received_ipv6_packet);
}

/*
    Check for any probes for which we have not received a response
    for some time, and report a time-out, assuming that we won't
    receive a future reply.
*/
void check_probe_timeouts(
    struct net_state_t *net_state)
{
    struct timeval now;
    struct probe_t *probe;
    int i;

    if (gettimeofday(&now, NULL)) {
        perror("gettimeofday failure");
        exit(1);
    }

    for (i = 0; i < MAX_PROBES; i++) {
        probe = &net_state->probes[i];

        /*  Don't check probes which aren't currently outstanding  */
        if (!probe->used) {
            continue;
        }

        if (compare_timeval(probe->platform.timeout_time, now) < 0) {
            /*  Report timeout to the command stream  */
            printf("%d no-reply\n", probe->token);

            free_probe(probe);
        }
    }
}

/*
    Find the remaining time until the next probe times out.
    This may be a negative value if the next probe timeout has
    already elapsed.

    Returns false if no probes are currently outstanding, and true
    if a timeout value for the next probe exists.
*/
bool get_next_probe_timeout(
    const struct net_state_t *net_state,
    struct timeval *timeout)
{
    int i;
    bool have_timeout;
    const struct probe_t *probe;
    struct timeval now;
    struct timeval probe_timeout;

    if (gettimeofday(&now, NULL)) {
        perror("gettimeofday failure");
        exit(1);
    }

    have_timeout = false;
    for (i = 0; i < MAX_PROBES; i++) {
        probe = &net_state->probes[i];
        if (!probe->used) {
            continue;
        }

        probe_timeout.tv_sec =
            probe->platform.timeout_time.tv_sec - now.tv_sec;
        probe_timeout.tv_usec =
            probe->platform.timeout_time.tv_usec - now.tv_usec;

        normalize_timeval(&probe_timeout);
        if (have_timeout) {
            if (compare_timeval(probe_timeout, *timeout) < 0) {
                /*  If this probe has a sooner timeout, store it instead  */
                *timeout = probe_timeout;
            }
        } else {
            *timeout = probe_timeout;
            have_timeout = true;
        }
    }

    return have_timeout;
}
