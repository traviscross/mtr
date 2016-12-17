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

#include "construct_unix.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "protocols.h"

/*  A source of data for computing a checksum  */
struct checksum_source_t
{
    const void *data;
    size_t size;
};

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

/*  Construct a header for IP version 4  */
static
void construct_ip4_header(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct sockaddr_storage *srcaddr,
    const struct sockaddr_storage *destaddr,
    const struct probe_param_t *param)
{
    struct IPHeader *ip;
    struct sockaddr_in *srcaddr4 = (struct sockaddr_in *)srcaddr;
    struct sockaddr_in *destaddr4 = (struct sockaddr_in *)destaddr;

    ip = (struct IPHeader *)&packet_buffer[0];

    memset(ip, 0, sizeof(struct IPHeader));

    ip->version = 0x45;
    ip->tos = param->type_of_service;
    ip->len = length_byte_swap(net_state, packet_size);
    ip->ttl = param->ttl;
    ip->protocol = param->protocol;
    memcpy(&ip->saddr, &srcaddr4->sin_addr, sizeof(uint32_t));
    memcpy(&ip->daddr, &destaddr4->sin_addr, sizeof(uint32_t));
}

/*  Construct an ICMP header for IPv4  */
static
void construct_icmp4_header(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct ICMPHeader *icmp;
    int icmp_size;

    icmp = (struct ICMPHeader *)&packet_buffer[sizeof(struct IPHeader)];
    icmp_size = packet_size - sizeof(struct IPHeader);

    memset(icmp, 0, sizeof(struct ICMPHeader));

    icmp->type = ICMP_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(param->command_token);
    icmp->checksum = htons(compute_checksum(icmp, icmp_size));
}

/*  Construct an ICMP header for IPv6  */
static
int construct_icmp6_packet(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct ICMPHeader *icmp;

    icmp = (struct ICMPHeader *)packet_buffer;

    memset(icmp, 0, sizeof(struct ICMPHeader));

    icmp->type = ICMP6_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(param->command_token);

    return 0;
}

/*
    Construct a header for UDP probes.  We'll use the source port
    as the command token, so that we can identify the probe when its
    header is returned embedded in an ICMP reply.
*/
static
void construct_udp4_header(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct UDPHeader *udp;
    int udp_size;

    udp = (struct UDPHeader *)&packet_buffer[sizeof(struct IPHeader)];
    udp_size = packet_size - sizeof(struct IPHeader);

    memset(udp, 0, sizeof(struct UDPHeader));

    udp->srcport = htons(param->command_token);
    udp->dstport = htons(param->dest_port);
    udp->length = htons(udp_size);
    udp->checksum = 0;
}

/*  Construct a header for UDPv6 probes  */
static
int construct_udp6_packet(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    int udp_socket = net_state->platform.udp6_send_socket;
    struct UDPHeader *udp;
    int udp_size;

    udp = (struct UDPHeader *)packet_buffer;
    udp_size = packet_size;

    memset(udp, 0, sizeof(struct UDPHeader));

    udp->srcport = htons(param->command_token);
    udp->dstport = htons(param->dest_port);
    udp->length = htons(udp_size);
    udp->checksum = 0;

    /*
        Instruct the kernel to put the pseudoheader checksum into the
        UDP header.
    */
    int chksum_offset = (char *)&udp->checksum - (char *)udp;
    if (setsockopt(
            udp_socket, IPPROTO_IPV6,
            IPV6_CHECKSUM, &chksum_offset, sizeof(int))) {
        return -1;
    }

    return 0;
}

/*
    Determine the size of the constructed packet based on the packet
    parameters.  This is the amount of space the packet *we* construct
    uses, and doesn't include any headers the operating system tacks
    onto the packet.  (Such as the IPv6 header on non-Linux operating
    systems.)
*/
static
int compute_packet_size(
    const struct net_state_t *net_state,
    const struct probe_param_t *param)
{
    int packet_size;

    /*  Start by determining the full size, including omitted headers  */
    if (param->ip_version == 6) {
        packet_size = sizeof(struct IP6Header);
    } else if (param->ip_version == 4) {
        packet_size = sizeof(struct IPHeader);
    } else {
        errno = EINVAL;
        return -1;
    }

    if (param->protocol == IPPROTO_ICMP) {
        packet_size += sizeof(struct ICMPHeader);
    } else if (param->protocol == IPPROTO_UDP) {
        packet_size += sizeof(struct UDPHeader);
    } else {
        errno = EINVAL;
        return -1;
    }

    /*
        If the requested size from send-probe is greater, extend the
        packet size.
    */
    if (param->packet_size > packet_size) {
        packet_size = param->packet_size;
    }

    /*
        Since we don't explicitly construct the IPv6 header, we
        need to account for it in our transmitted size.
    */
    if (param->ip_version == 6) {
        packet_size -= sizeof(struct IP6Header);
    }

    return packet_size;
}

/*  Construct a packet for an IPv4 probe  */
int construct_ip4_packet(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct sockaddr_storage *src_sockaddr,
    const struct sockaddr_storage *dest_sockaddr,
    const struct probe_param_t *param)
{
    construct_ip4_header(
        net_state, packet_buffer, packet_size,
        src_sockaddr, dest_sockaddr, param);

    if (param->protocol == IPPROTO_ICMP) {
        construct_icmp4_header(
            net_state, packet_buffer, packet_size, param);
    } else if (param->protocol == IPPROTO_UDP) {
        construct_udp4_header(
            net_state, packet_buffer, packet_size, param);
    } else {
        errno = EINVAL;
        return -1;
    }

    /*
        The routing mark requires CAP_NET_ADMIN, as opposed to the
        CAP_NET_RAW which we are sometimes explicitly given.
        If we don't have CAP_NET_ADMIN, this will fail, so we'll 
        only set the mark if the user has explicitly requested it.

        Unfortunately, this means that once the mark is set, it won't
        be set on the socket again until a new mark is explicitly
        specified.
    */
#ifdef SO_MARK
    if (param->routing_mark) {
        if (setsockopt(
                net_state->platform.ip4_send_socket,
                SOL_SOCKET, SO_MARK, &param->routing_mark, sizeof(int))) {
            return -1;
        }
    }
#endif

    return 0;
}

/*  Construct a packet for an IPv6 probe  */
int construct_ip6_packet(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct sockaddr_storage *src_sockaddr,
    const struct sockaddr_storage *dest_sockaddr,
    const struct probe_param_t *param)
{
    int send_socket;

    if (param->protocol == IPPROTO_ICMP) {
        send_socket = net_state->platform.icmp6_send_socket;

        if (construct_icmp6_packet(
                net_state, packet_buffer, packet_size, param)) {
            return -1;
        }
    } else if (param->protocol == IPPROTO_UDP) {
        send_socket = net_state->platform.udp6_send_socket;

        if (construct_udp6_packet(
                net_state, packet_buffer, packet_size, param)) {
            return -1;
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    /*  The traffic class in IPv6 is analagous to ToS in IPv4  */
    if (setsockopt(
            send_socket, IPPROTO_IPV6,
            IPV6_TCLASS, &param->type_of_service, sizeof(int))) {
        return -1;
    }

    /*  Set the time-to-live  */
    if (setsockopt(
            send_socket, IPPROTO_IPV6,
            IPV6_UNICAST_HOPS, &param->ttl, sizeof(int))) {
        return -1;
    }

#ifdef SO_MARK
    if (param->routing_mark) {
        if (setsockopt(
                send_socket,
                SOL_SOCKET, SO_MARK, &param->routing_mark, sizeof(int))) {
            return -1;
        }
    }
#endif

    return 0;
}

/*  Construct a probe packet based on the probe parameters  */
int construct_packet(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_buffer_size,
    const struct sockaddr_storage *dest_sockaddr,
    const struct probe_param_t *param)
{
    int packet_size;
    struct sockaddr_storage src_sockaddr;

    packet_size = compute_packet_size(net_state, param);
    if (packet_size < 0) {
        return -1;
    }

    if (packet_buffer_size < packet_size) {
        errno = EINVAL;
        return -1;
    }

    if (find_source_addr(&src_sockaddr, dest_sockaddr)) {
        return -1;
    }

    memset(packet_buffer, param->bit_pattern, packet_size);

    if (param->ip_version == 6) {
        if (construct_ip6_packet(
                net_state, packet_buffer, packet_size,
                &src_sockaddr, dest_sockaddr, param)) {
            return -1;
        }
    } else if (param->ip_version == 4) {
        if (construct_ip4_packet(
                net_state, packet_buffer, packet_size,
                &src_sockaddr, dest_sockaddr, param)) {
            return -1;
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    return packet_size;
}
