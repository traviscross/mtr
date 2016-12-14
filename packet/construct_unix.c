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

    ip->version = 0x45;
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

    icmp->type = ICMP6_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(param->command_token);

    if (setsockopt(
            net_state->platform.icmp6_send_socket, IPPROTO_IPV6,
            IPV6_UNICAST_HOPS, &param->ttl, sizeof(int))) {
        return -errno;
    }

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

    udp->srcport = htons(param->command_token);
    udp->dstport = htons(param->dest_port);
    udp->length = htons(udp_size);
    udp->checksum = 0;

    /*  Set the TTL via setsockopt  */
    if (setsockopt(
            udp_socket, IPPROTO_IPV6,
            IPV6_UNICAST_HOPS, &param->ttl, sizeof(int))) {

        return -errno;
    }

    /*
        Instruct the kernel to put the pseudoheader checksum into the
        UDP header.
    */
    int chksum_offset = (char *)&udp->checksum - (char *)udp;
    if (setsockopt(
            udp_socket, IPPROTO_IPV6,
            IPV6_CHECKSUM, &chksum_offset, sizeof(int))) {

        return -errno;
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

    if (param->ip_version == 6) {
        packet_size = 0;
    } else if (param->ip_version == 4) {
        packet_size = sizeof(struct IPHeader);
    } else {
        return -EINVAL;
    }

    if (param->protocol == IPPROTO_ICMP) {
        packet_size += sizeof(struct ICMPHeader);
    } else if (param->protocol == IPPROTO_UDP) {
        packet_size += sizeof(struct UDPHeader);
    } else {
        return -EINVAL;
    }

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

    err = 0;
    if (param->ip_version == 6) {
        if (param->protocol == IPPROTO_ICMP) {
            err = construct_icmp6_packet(
                net_state, packet_buffer, packet_size, param);
        } else if (param->protocol == IPPROTO_UDP) {
            err = construct_udp6_packet(
                net_state, packet_buffer, packet_size, param);
        } else {
            return -EINVAL;
        }
    } else {
        construct_ip4_header(
            net_state, packet_buffer, packet_size,
            &src_sockaddr, dest_sockaddr, param);

        if (param->protocol == IPPROTO_ICMP) {
            construct_icmp4_header(
                net_state, packet_buffer, packet_size, param);
        } else if (param->protocol == IPPROTO_UDP) {
            construct_udp4_header(
                net_state, packet_buffer, packet_size, param);
        } else {
            return -EINVAL;
        }
    }

    if (err) {
        return err;
    }

    return packet_size;
}
