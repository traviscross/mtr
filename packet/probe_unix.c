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

#include "protocols.h"
#include "timeval.h"

/*  Use the "jumbo" frame size as the max packet size  */
#define PACKET_BUFFER_SIZE 9000

/*  Compute the IP checksum (or ICMP checksum) of a packet.  */
static
uint16_t compute_checksum(
    const void *packet,
    int size)
{
    const uint8_t *packet_bytes = (uint8_t *)packet;
    uint32_t sum = 0;
    int i;

    for (i = 0; i < size; i++) {
        if ((i & 1) == 0) {
            sum += packet_bytes[i] << 8;
        } else {
            sum += packet_bytes[i];
        }
    }

    /*
        Sums which overflow a 16-bit value have the high bits
        added back into the low 16 bits.
    */
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    /*
        The value stored is the one's complement of the
        mathematical sum.
    */
    return (~sum & 0xffff);
}

/*  Encode the IP header length field in the order required by the OS.  */
static
uint16_t length_byte_swap(
    const struct net_state_t *net_state,
    uint16_t length)
{
    if (net_state->platform.ip_length_host_order) {
        return length;
    } else {
        return htons(length);
    }
}

/*  Construct a probe packet based on the probe parameters  */
static
int construct_packet(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_buffer_size,
    struct sockaddr_in dest_sockaddr,
    const struct probe_param_t *param)
{
    struct IPHeader *ip;
    struct ICMPHeader *icmp;
    int packet_size;
    int icmp_size;

    ip = (struct IPHeader *)&packet_buffer[0];
    icmp = (struct ICMPHeader *)(ip + 1);
    packet_size = sizeof(struct IPHeader) + sizeof(struct ICMPHeader);
    icmp_size = packet_size - sizeof(struct IPHeader);

    if (packet_buffer_size < packet_size) {
        return -EINVAL;
    }

    memset(packet_buffer, 0, packet_size);

    /*  Fill the IP header  */
    ip->version = 0x45;
    ip->len = length_byte_swap(net_state, packet_size);
    ip->ttl = param->ttl;
    ip->protocol = IPPROTO_ICMP;
    memcpy(&ip->daddr, &dest_sockaddr.sin_addr, sizeof(uint32_t));

    /*  Fill the ICMP header  */
    icmp->type = ICMP_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(param->command_token);
    icmp->checksum = htons(compute_checksum(icmp, icmp_size));

    return packet_size;
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
    struct sockaddr_in dest_sockaddr;
    ssize_t bytes_sent;
    int packet_size;

    memset(&param, 0, sizeof(struct probe_param_t));
    param.ttl = 255;
    param.ipv4_address = "127.0.0.1";

    if (decode_dest_addr(&param, &dest_sockaddr)) {
        fprintf(stderr, "Error decoding localhost address\n");
        exit(1);
    }

    /*  First attempt to ping the localhost with network byte order  */
    net_state->platform.ip_length_host_order = false;

    packet_size = construct_packet(
        net_state, packet, PACKET_BUFFER_SIZE, dest_sockaddr, &param);
    assert(packet_size > 0);

    bytes_sent = sendto(
        net_state->platform.ipv4_send_socket,
        packet, packet_size, 0,
        (struct sockaddr *)&dest_sockaddr,
        sizeof(struct sockaddr_in));

    if (bytes_sent > 0) {
        return;
    }

    /*  Since network byte order failed, try host byte order  */
    net_state->platform.ip_length_host_order = true;

    packet_size = construct_packet(
        net_state, packet, PACKET_BUFFER_SIZE, dest_sockaddr, &param);
    assert(packet_size > 0);

    bytes_sent = sendto(
        net_state->platform.ipv4_send_socket,
        packet, packet_size, 0,
        (struct sockaddr *)&dest_sockaddr,
        sizeof(struct sockaddr_in));

    if (bytes_sent < 0) {
        perror("Unable to send with swapped length");
        exit(1);
    }
}

/*  Open the raw sockets for transmitting custom crafted packets  */
void init_net_state(
    struct net_state_t *net_state)
{
    int send_socket;
    int recv_socket;
    int flags;
    int trueopt = 1;

    memset(net_state, 0, sizeof(struct net_state_t));

    send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_socket == -1) {
        perror("Failure opening raw socket");
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
        perror("Failure opening raw socket");
        exit(1);
    }

    flags = fcntl(recv_socket, F_GETFL, 0);
    if (flags == -1) {
        perror("Unexpected socket error");
        exit(1);
    }

    /*  Set the receive socket to be non-blocking  */
    if (fcntl(recv_socket, F_SETFL, flags | O_NONBLOCK)) {
        perror("Unexpected socket error");
        exit(1);
    }

    net_state->platform.ipv4_send_socket = send_socket;
    net_state->platform.ipv4_recv_socket = recv_socket;

    check_length_order(net_state);
}

/*  Craft a custom ICMP packet for a network probe.  */
void send_probe(
    struct net_state_t *net_state,
    const struct probe_param_t *param)
{
    char packet[PACKET_BUFFER_SIZE];
    struct sockaddr_in dest_sockaddr;
    struct probe_t *probe;
    int packet_size;

    if (decode_dest_addr(param, &dest_sockaddr)) {
        printf("%d invalid-argument\n", param->command_token);
        return;
    }

    packet_size = construct_packet(
        net_state, packet, PACKET_BUFFER_SIZE, dest_sockaddr, param);
    if (packet_size < 0) {
        printf("%d invalid-argument\n", param->command_token);
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

    if (sendto(
            net_state->platform.ipv4_send_socket,
            packet, packet_size, 0,
            (struct sockaddr *)&dest_sockaddr,
            sizeof(struct sockaddr_in)) == -1) {

        perror("Failure sending probe");
        exit(1);
    }

    probe->platform.timeout_time = probe->platform.departure_time;
    probe->platform.timeout_time.tv_sec += param->timeout;
}

/*
    Compute the round trip time of a just-received probe and pass it
    to the platform agnostic response handling.
*/
static
void receive_probe(
    struct probe_t *probe,
    int icmp_type,
    struct sockaddr_in remote_addr,
    struct timeval timestamp)
{
    unsigned int round_trip_us;

    round_trip_us =
        (timestamp.tv_sec - probe->platform.departure_time.tv_sec) * 1000000 +
        timestamp.tv_usec - probe->platform.departure_time.tv_usec;

    respond_to_probe(probe, icmp_type, remote_addr, round_trip_us);
}

/*
    Called when we have received a new packet through our raw socket.
    We'll check to see that it is a response to one of our probes, and
    if so, report the result of the probe to our command stream.
*/
static
void handle_received_packet(
    struct net_state_t *net_state,
    struct sockaddr_in remote_addr,
    const void *packet,
    int packet_length,
    struct timeval timestamp)
{
    const int ip_icmp_size =
        sizeof(struct IPHeader) + sizeof(struct ICMPHeader);
    const int ip_icmp_ip_icmp_size = 
        sizeof(struct IPHeader) + sizeof(struct ICMPHeader) +
        sizeof(struct IPHeader) + sizeof(struct ICMPHeader);
    const struct IPHeader *ip;
    const struct ICMPHeader *icmp;
    const struct IPHeader *inner_ip;
    const struct ICMPHeader *inner_icmp;
    struct probe_t *probe;

    /*  Ensure that we don't access memory beyond the bounds of the packet  */
    if (packet_length < ip_icmp_size) {
        return;
    }

    ip = (struct IPHeader *)packet;
    if (ip->protocol != IPPROTO_ICMP) {
        return;
    }

    icmp = (struct ICMPHeader *)(ip + 1);

    /*  If we get an echo reply, our probe reached the destination host  */
    if (icmp->type == ICMP_ECHOREPLY) {
        probe = find_probe(net_state, icmp->id, icmp->sequence);
        if (probe == NULL) {
            return;
        }

        receive_probe(probe, icmp->type, remote_addr, timestamp);
    }

    /*
        If we get a time exceeded, we got a response from an intermediate
        host along the path to our destination.
    */
    if (icmp->type == ICMP_TIME_EXCEEDED) {
        if (packet_length < ip_icmp_ip_icmp_size) {
            return;
        }

        /*
            The IP packet inside the ICMP response contains our original
            IP header.  That's where we can get our original ID and
            sequence number.
        */
        inner_ip = (struct IPHeader *)(icmp + 1);
        inner_icmp = (struct ICMPHeader *)(inner_ip + 1);

        probe = find_probe(net_state, inner_icmp->id, inner_icmp->sequence);
        if (probe == NULL) {
            return;
        }

        receive_probe(probe, icmp->type, remote_addr, timestamp);
    }
}

/*
    Read all available packets through our receiving raw socket, and
    handle any responses to probes we have preivously sent.
*/
void receive_replies(
    struct net_state_t *net_state)
{
    char packet[PACKET_BUFFER_SIZE];
    int packet_length;
    struct sockaddr_in remote_addr;
    socklen_t sockaddr_length;
    struct timeval timestamp;

    /*  Read until no more packets are available  */
    while (true) {
        sockaddr_length = sizeof(struct sockaddr_in);
        packet_length = recvfrom(
            net_state->platform.ipv4_recv_socket,
            packet, PACKET_BUFFER_SIZE, 0,
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
            net_state, remote_addr, packet, packet_length, timestamp);
    }
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
