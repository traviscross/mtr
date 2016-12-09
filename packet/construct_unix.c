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
#include <string.h>
#include <unistd.h>

#include "protocols.h"

/*  A source of data for computing a checksum  */
struct checksum_source_t
{
    const void *data;
    size_t size;
};

/*
    Compute the IP checksum (or ICMP checksum) of a packet.
    We may need to use data from multiple sources, to checksum
    the "psuedo-header" for UDP or ICMPv6.
*/
static
uint16_t compute_checksum(
    struct checksum_source_t *source,
    int source_count)
{
    int i, j;
    const uint8_t *bytes;
    size_t size;
    uint32_t sum = 0;

    for (i = 0; i < source_count; i++) {
        bytes = (uint8_t *)source[i].data;
        size = source[i].size;

        for (j = 0; j < size; j++) {
            if ((j & 1) == 0) {
                sum += bytes[j] << 8;
            } else {
                sum += bytes[j];
            }
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

/*  Compute the checksum from a single source of data  */
static
uint16_t simple_checksum(
    const void *packet,
    size_t size)
{
    struct checksum_source_t source;

    source.data = packet;
    source.size = size;

    return compute_checksum(&source, 1);
}

/*
    ICMPv6 and UDPv6 use a pseudo-header with a different layout
    from the real IPv6 header for checksum purposes.  We'll fill
    in the psuedo-header and use it to start the checksum against
    the packet.
*/
static
uint16_t pseudo6_checksum(
    const void *ip_packet,
    const void *packet,
    size_t size)
{
    const struct IP6Header *ip = (struct IP6Header *)ip_packet;
    struct IP6PseudoHeader pseudo;
    struct checksum_source_t source[2];

    memcpy(pseudo.saddr, ip->saddr, sizeof(struct in6_addr));
    memcpy(pseudo.daddr, ip->daddr, sizeof(struct in6_addr));
    pseudo.len = ip->len;
    memset(pseudo.zero, 0, sizeof(pseudo.zero));
    pseudo.protocol = ip->protocol;

    source[0].data = &pseudo;
    source[0].size = sizeof(struct IP6PseudoHeader);
    source[1].data = packet;
    source[1].size = size;

    return compute_checksum(source, 2);
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

    ip->version = 0x45;
    ip->len = length_byte_swap(net_state, packet_size);
    ip->ttl = param->ttl;
    ip->protocol = IPPROTO_ICMP;
    memcpy(&ip->saddr, &srcaddr4->sin_addr, sizeof(uint32_t));
    memcpy(&ip->daddr, &destaddr4->sin_addr, sizeof(uint32_t));
}

/*  Construct a header for IP version 6  */
static
void construct_ip6_header(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct sockaddr_storage *srcaddr,
    const struct sockaddr_storage *destaddr,
    const struct probe_param_t *param)
{
    struct IP6Header *ip;
    int payload_size;
    struct sockaddr_in6 *srcaddr6 = (struct sockaddr_in6 *)srcaddr;
    struct sockaddr_in6 *destaddr6 = (struct sockaddr_in6 *)destaddr;

    if (!net_state->platform.ipv6_header_constructed) {
        return;
    }

    ip = (struct IP6Header *)&packet_buffer[0];
    payload_size = packet_size - sizeof(struct IP6Header);

    ip->version = 0x60;
    ip->len = htons(payload_size);
    ip->protocol = IPPROTO_ICMPV6;
    ip->ttl = param->ttl;
    memcpy(&ip->saddr, &srcaddr6->sin6_addr, sizeof(struct in6_addr));
    memcpy(&ip->daddr, &destaddr6->sin6_addr, sizeof(struct in6_addr));
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

    icmp->type = ICMP_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(param->command_token);
    icmp->checksum = htons(simple_checksum(icmp, icmp_size));
}

/*  Construct an ICMP header for IPv6  */
static
void construct_icmp6_header(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct ICMPHeader *icmp;
    int icmp_size;

    if (net_state->platform.ipv6_header_constructed) {
        icmp = (struct ICMPHeader *)&packet_buffer[sizeof(struct IP6Header)];
        icmp_size = packet_size - sizeof(struct IP6Header);
    } else {
        icmp = (struct ICMPHeader *)packet_buffer;
        icmp_size = packet_size;
    }

    icmp->type = ICMP6_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(param->command_token);

    if (net_state->platform.ipv6_header_constructed) {
        icmp->checksum = htons(
            pseudo6_checksum(packet_buffer, icmp, icmp_size));
    }
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
    int packet_size = 0;

    if (param->ip_version == 6) {
        if (net_state->platform.ipv6_header_constructed) {
            packet_size = sizeof(struct IP6Header);
        }
    } else if (param->ip_version == 4) {
        packet_size = sizeof(struct IPHeader);
    } else {
        return -EINVAL;
    }
    packet_size += sizeof(struct ICMPHeader);

    return packet_size;
}

/*  Construct a probe packet based on the probe parameters  */
int construct_packet(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_buffer_size,
    const struct sockaddr_storage *dest_sockaddr,
    const struct probe_param_t *param)
{
    int err;
    int packet_size;
    struct sockaddr_storage src_sockaddr;

    packet_size = compute_packet_size(net_state, param);
    if (packet_size < 0) {
        return packet_size;
    }

    if (packet_buffer_size < packet_size) {
        return -EINVAL;
    }

    err = find_source_addr(&src_sockaddr, dest_sockaddr);
    if (err) {
        return err;
    }

    memset(packet_buffer, 0, packet_size);

    if (param->ip_version == 6) {
        construct_ip6_header(
            net_state, packet_buffer, packet_size,
            &src_sockaddr, dest_sockaddr, param);
        construct_icmp6_header(
            net_state, packet_buffer, packet_size, param);
    } else {
        construct_ip4_header(
            net_state, packet_buffer, packet_size,
            &src_sockaddr, dest_sockaddr, param);
        construct_icmp4_header(
            net_state, packet_buffer, packet_size, param);
    }

    return packet_size;
}
