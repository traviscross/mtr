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

#include "deconstruct_unix.h"

#include <stdio.h>
#include <stdlib.h>

#include "protocols.h"

/*
    Compute the round trip time of a just-received probe and pass it
    to the platform agnostic response handling.
*/
static
void receive_probe(
    struct probe_t *probe,
    int icmp_type,
    const struct sockaddr_storage *remote_addr,
    struct timeval timestamp)
{
    unsigned int round_trip_us;

    round_trip_us =
        (timestamp.tv_sec - probe->platform.departure_time.tv_sec) * 1000000 +
        timestamp.tv_usec - probe->platform.departure_time.tv_usec;

    respond_to_probe(probe, icmp_type, remote_addr, round_trip_us);
}

/*
    Given an ICMP id + ICMP sequence, find the match probe we've
    transmitted and if found, respond to the command which sent it
*/
static
void find_and_receive_probe(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    struct timeval timestamp,
    int icmp_type,
    int icmp_id,
    int icmp_sequence)
{
    struct probe_t *probe;

    probe = find_probe(net_state, icmp_id, icmp_sequence);
    if (probe == NULL) {
        return;
    }

    receive_probe(probe, icmp_type, remote_addr, timestamp);
}

/*
    Decode the ICMP header received and try to find a probe which it
    is in response to.
*/
static
void handle_received_icmpv4_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    const struct ICMPHeader *icmp,
    int packet_length,
    struct timeval timestamp)
{
    const int icmp_ip_icmp_size =
        sizeof(struct ICMPHeader) +
        sizeof(struct IPHeader) + sizeof(struct ICMPHeader);
    const struct IPHeader *inner_ip;
    const struct ICMPHeader *inner_icmp;

    /*  If we get an echo reply, our probe reached the destination host  */
    if (icmp->type == ICMP_ECHOREPLY) {
        find_and_receive_probe(
            net_state, remote_addr, timestamp,
            ICMP_ECHOREPLY, icmp->id, icmp->sequence);
    }

    /*
        If we get a time exceeded, we got a response from an intermediate
        host along the path to our destination.
    */
    if (icmp->type == ICMP_TIME_EXCEEDED) {
        if (packet_length < icmp_ip_icmp_size) {
            return;
        }

        /*
            The IP packet inside the ICMP response contains our original
            IP header.  That's where we can get our original ID and
            sequence number.
        */
        inner_ip = (struct IPHeader *)(icmp + 1);
        inner_icmp = (struct ICMPHeader *)(inner_ip + 1);

        find_and_receive_probe(
            net_state, remote_addr, timestamp,
            ICMP_TIME_EXCEEDED, inner_icmp->id, inner_icmp->sequence);
    }
}

/*
    Decode the ICMPv6 header.  The code duplication with ICMPv4 is
    unfortunate, but small details in structure size and ICMP
    constants differ.
*/
static
void handle_received_icmpv6_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    const struct ICMPHeader *icmp,
    int packet_length,
    struct timeval timestamp)
{
    const int icmp_ip_icmp_size =
        sizeof(struct ICMPHeader) +
        sizeof(struct IP6Header) + sizeof(struct ICMPHeader);
    const struct IP6Header *inner_ip;
    const struct ICMPHeader *inner_icmp;

    if (icmp->type == ICMP6_ECHOREPLY) {
        find_and_receive_probe(
            net_state, remote_addr, timestamp,
            ICMP_ECHOREPLY, icmp->id, icmp->sequence);
    }

    if (icmp->type == ICMP6_TIME_EXCEEDED) {
        if (packet_length < icmp_ip_icmp_size) {
            return;
        }

        inner_ip = (struct IP6Header *)(icmp + 1);
        inner_icmp = (struct ICMPHeader *)(inner_ip + 1);

        find_and_receive_probe(
            net_state, remote_addr, timestamp,
            ICMP_TIME_EXCEEDED, inner_icmp->id, inner_icmp->sequence);
    }
}

/*
    We've received a new IPv4 ICMP packet.
    We'll check to see that it is a response to one of our probes, and
    if so, report the result of the probe to our command stream.
*/
void handle_received_ipv4_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    const void *packet,
    int packet_length,
    struct timeval timestamp)
{
    const int ip_icmp_size =
        sizeof(struct IPHeader) + sizeof(struct ICMPHeader);
    const struct IPHeader *ip;
    const struct ICMPHeader *icmp;
    int icmp_length;

    /*  Ensure that we don't access memory beyond the bounds of the packet  */
    if (packet_length < ip_icmp_size) {
        return;
    }

    ip = (struct IPHeader *)packet;
    if (ip->protocol != IPPROTO_ICMP) {
        return;
    }

    icmp = (struct ICMPHeader *)(ip + 1);
    icmp_length = packet_length - sizeof(struct IPHeader);

    handle_received_icmpv4_packet(
        net_state, remote_addr, icmp, icmp_length, timestamp);
}

/*
    Unlike ICMPv6 raw sockets, unlike ICMPv4, don't include the IP header
    in received packets, so we can assume the packet we got starts
    with the ICMP packet.
*/
void handle_received_ipv6_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    const void *packet,
    int packet_length,
    struct timeval timestamp)
{
    const struct ICMPHeader *icmp;

    icmp = (struct ICMPHeader *)packet;

    handle_received_icmpv6_packet(
        net_state, remote_addr, icmp, packet_length, timestamp);
}
