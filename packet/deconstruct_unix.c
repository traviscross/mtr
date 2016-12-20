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
    Given an ICMP id + ICMP sequence, find the match probe we've
    transmitted and if found, respond to the command which sent it
*/
static
void find_and_receive_probe(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    struct timeval *timestamp,
    int icmp_type,
    int protocol,
    int icmp_id,
    int icmp_sequence)
{
    struct probe_t *probe;

    probe = find_probe(net_state, protocol, icmp_id, icmp_sequence);
    if (probe == NULL) {
        return;
    }

    receive_probe(probe, icmp_type, remote_addr, timestamp);
}

/*
    We've received an ICMP message with an embedded IP packet.
    We will try to determine which of our outgoing probes
    corresponds to the embedded IP packet and record the response.
*/
static
void handle_inner_ip4_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    int icmp_result,
    const struct IPHeader *ip,
    int packet_length,
    struct timeval *timestamp)
{
    const int ip_icmp_size =
        sizeof(struct IPHeader) + sizeof(struct ICMPHeader);
    const int ip_udp_size =
        sizeof(struct IPHeader) + sizeof(struct UDPHeader);
    const int ip_tcp_size =
        sizeof(struct IPHeader) + sizeof(struct TCPHeader);
    const int ip_sctp_size =
        sizeof(struct IPHeader) + sizeof(struct SCTPHeader);
    const struct ICMPHeader *icmp;
    const struct UDPHeader *udp;
    const struct TCPHeader *tcp;
    const struct SCTPHeader *sctp;

    if (ip->protocol == IPPROTO_ICMP) {
        if (packet_length < ip_icmp_size) {
            return;
        }

        icmp = (struct ICMPHeader *)(ip + 1);

        find_and_receive_probe(
            net_state, remote_addr, timestamp, icmp_result,
            IPPROTO_ICMP, icmp->id, icmp->sequence);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (packet_length < ip_udp_size) {
            return;
        }

        udp = (struct UDPHeader *)(ip + 1);

        find_and_receive_probe(
            net_state, remote_addr, timestamp, icmp_result,
            IPPROTO_UDP, 0, udp->srcport);
    } else if (ip->protocol == IPPROTO_TCP) {
        if (packet_length < ip_tcp_size) {
            return;
        }

        tcp = (struct TCPHeader *)(ip + 1);

        find_and_receive_probe(
            net_state, remote_addr, timestamp, icmp_result,
            IPPROTO_TCP, 0, tcp->srcport);
#ifdef IPPROTO_SCTP
    } else if (ip->protocol == IPPROTO_SCTP) {
        if (packet_length < ip_sctp_size) {
            return;
        }

        sctp = (struct SCTPHeader *)(ip + 1);

        find_and_receive_probe(
            net_state, remote_addr, timestamp, icmp_result,
            IPPROTO_SCTP, 0, sctp->srcport);
#endif
    }
}

/*
    Examine the IPv6 header embedded in a returned ICMPv6 packet
    in order to match it with a probe which we previously sent.
*/
static
void handle_inner_ip6_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    int icmp_result,
    const struct IP6Header *ip,
    int packet_length,
    struct timeval *timestamp)
{
    const int ip_icmp_size =
        sizeof(struct IP6Header) + sizeof(struct ICMPHeader);
    const int ip_udp_size =
        sizeof(struct IP6Header) + sizeof(struct UDPHeader);
    const int ip_tcp_size =
        sizeof(struct IP6Header) + sizeof(struct TCPHeader);
    const int ip_sctp_size =
        sizeof(struct IPHeader) + sizeof(struct SCTPHeader);
    const struct ICMPHeader *icmp;
    const struct UDPHeader *udp;
    const struct TCPHeader *tcp;
    const struct SCTPHeader *sctp;

    if (ip->protocol == IPPROTO_ICMPV6) {
        if (packet_length < ip_icmp_size) {
            return;
        }

        icmp = (struct ICMPHeader *)(ip + 1);

        find_and_receive_probe(
            net_state, remote_addr, timestamp, icmp_result,
            IPPROTO_ICMP, icmp->id, icmp->sequence);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (packet_length < ip_udp_size) {
            return;
        }

        udp = (struct UDPHeader *)(ip + 1);

        find_and_receive_probe(
            net_state, remote_addr, timestamp, icmp_result,
            IPPROTO_UDP, 0, udp->srcport);
    } else if (ip->protocol == IPPROTO_TCP) {
        if (packet_length < ip_tcp_size) {
            return;
        }

        tcp = (struct TCPHeader *)(ip + 1);
        find_and_receive_probe(
            net_state, remote_addr, timestamp, icmp_result,
            IPPROTO_TCP, 0, tcp->srcport);
#ifdef IPPROTO_SCTP
    } else if (ip->protocol == IPPROTO_SCTP) {
        if (packet_length < ip_sctp_size) {
            return;
        }

        sctp = (struct SCTPHeader *)(ip + 1);

        find_and_receive_probe(
            net_state, remote_addr, timestamp, icmp_result,
            IPPROTO_SCTP, 0, sctp->srcport);
#endif
    }
}

/*
    Decode the ICMP header received and try to find a probe which it
    is in response to.
*/
static
void handle_received_icmp4_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    const struct ICMPHeader *icmp,
    int packet_length,
    struct timeval *timestamp)
{
    const int icmp_ip_size =
        sizeof(struct ICMPHeader) + sizeof(struct IPHeader);
    const struct IPHeader *inner_ip;
    int inner_size = packet_length - sizeof(struct ICMPHeader);

    /*  If we get an echo reply, our probe reached the destination host  */
    if (icmp->type == ICMP_ECHOREPLY) {
        find_and_receive_probe(
            net_state, remote_addr, timestamp,
            ICMP_ECHOREPLY, IPPROTO_ICMP, icmp->id, icmp->sequence);
    }

    if (packet_length < icmp_ip_size) {
        return;
    }
    inner_ip = (struct IPHeader *)(icmp + 1);

    /*
        If we get a time exceeded, we got a response from an intermediate
        host along the path to our destination.
    */
    if (icmp->type == ICMP_TIME_EXCEEDED) {
        /*
            The IP packet inside the ICMP response contains our original
            IP header.  That's where we can get our original ID and
            sequence number.
        */
        handle_inner_ip4_packet(
            net_state, remote_addr,
            ICMP_TIME_EXCEEDED, inner_ip, inner_size, timestamp);
    }

    if (icmp->type == ICMP_DEST_UNREACH) {
        /*
            We'll get a ICMP_PORT_UNREACH when a non-ICMP probe
            reaches its final destination.  (Assuming that port isn't
            open on the destination host.)
        */
        if (icmp->code == ICMP_PORT_UNREACH) {
            handle_inner_ip4_packet(
                net_state, remote_addr,
                ICMP_ECHOREPLY, inner_ip, inner_size, timestamp);
        }
    }
}

/*
    Decode the ICMPv6 header.  The code duplication with ICMPv4 is
    unfortunate, but small details in structure size and ICMP
    constants differ.
*/
static
void handle_received_icmp6_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    const struct ICMPHeader *icmp,
    int packet_length,
    struct timeval *timestamp)
{
    const int icmp_ip_size =
        sizeof(struct ICMPHeader) + sizeof(struct IP6Header);
    const struct IP6Header *inner_ip;
    int inner_size = packet_length - sizeof(struct ICMPHeader);

    if (icmp->type == ICMP6_ECHOREPLY) {
        find_and_receive_probe(
            net_state, remote_addr, timestamp, ICMP_ECHOREPLY,
            IPPROTO_ICMP, icmp->id, icmp->sequence);
    }

    if (packet_length < icmp_ip_size) {
        return;
    }
    inner_ip = (struct IP6Header *)(icmp + 1);

    if (icmp->type == ICMP6_TIME_EXCEEDED) {
        handle_inner_ip6_packet(
            net_state, remote_addr,
            ICMP_TIME_EXCEEDED, inner_ip, inner_size, timestamp);
    }

    if (icmp->type == ICMP6_DEST_UNREACH) {
        if (icmp->code == ICMP6_PORT_UNREACH) {
            handle_inner_ip6_packet(
                net_state, remote_addr,
                ICMP_ECHOREPLY, inner_ip, inner_size, timestamp);
        }
    }
}

/*
    We've received a new IPv4 ICMP packet.
    We'll check to see that it is a response to one of our probes, and
    if so, report the result of the probe to our command stream.
*/
void handle_received_ip4_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    const void *packet,
    int packet_length,
    struct timeval *timestamp)
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

    handle_received_icmp4_packet(
        net_state, remote_addr, icmp, icmp_length, timestamp);
}

/*
    Unlike ICMPv6 raw sockets, unlike ICMPv4, don't include the IP header
    in received packets, so we can assume the packet we got starts
    with the ICMP packet.
*/
void handle_received_ip6_packet(
    struct net_state_t *net_state,
    const struct sockaddr_storage *remote_addr,
    const void *packet,
    int packet_length,
    struct timeval *timestamp)
{
    const struct ICMPHeader *icmp;

    icmp = (struct ICMPHeader *)packet;

    handle_received_icmp6_packet(
        net_state, remote_addr, icmp, packet_length, timestamp);
}
