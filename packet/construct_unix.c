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

#include "construct_unix.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "protocols.h"
#include "sockaddr.h"

/* For Mac OS X and FreeBSD */
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

/*  A source of data for computing a checksum  */
struct checksum_source_t {
    const void *data;
    size_t size;
};

/*  Compute the IP checksum (or ICMP checksum) of a packet.  */
static
uint16_t compute_checksum(
    const void *packet,
    int size)
{
    const uint8_t *packet_bytes = (uint8_t *) packet;
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

/*  Construct a combined sockaddr from a source address and source port  */
static
void construct_addr_port(
    struct sockaddr_storage *addr_with_port,
    const struct sockaddr_storage *addr,
    int port)
{
    memcpy(addr_with_port, addr, sizeof(struct sockaddr_storage));
    *sockaddr_port_offset(addr_with_port) = htons(port);
}

/*  Construct a header for IP version 4  */
static
void construct_ip4_header(
    const struct net_state_t *net_state,
    const struct probe_t *probe,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct IPHeader *ip;

    ip = (struct IPHeader *) &packet_buffer[0];

    memset(ip, 0, sizeof(struct IPHeader));

    ip->version = 0x45;
    ip->tos = param->type_of_service;
    ip->len = length_byte_swap(net_state, packet_size);
    ip->ttl = param->ttl;
    ip->protocol = param->protocol;
//    ip->id = htons(getpid());
    memcpy(&ip->saddr,
           sockaddr_addr_offset(&probe->local_addr),
           sockaddr_addr_size(&probe->local_addr));
    memcpy(&ip->daddr,
           sockaddr_addr_offset(&probe->remote_addr),
           sockaddr_addr_size(&probe->remote_addr));
}

/*  Construct an ICMP header for IPv4  */
static
void construct_icmp4_header(
    const struct net_state_t *net_state,
    struct probe_t *probe,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct ICMPHeader *icmp;
    int icmp_size;

    if (net_state->platform.ip4_socket_raw) {
        icmp = (struct ICMPHeader *) &packet_buffer[sizeof(struct IPHeader)];
        icmp_size = packet_size - sizeof(struct IPHeader);
    } else {
        icmp = (struct ICMPHeader *) &packet_buffer[0];
        icmp_size = packet_size;
    }

    memset(icmp, 0, sizeof(struct ICMPHeader));

    icmp->type = ICMP_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(probe->sequence);
    icmp->checksum = htons(compute_checksum(icmp, icmp_size));
}

/*  Construct an ICMP header for IPv6  */
static
int construct_icmp6_packet(
    const struct net_state_t *net_state,
    struct probe_t *probe,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct ICMPHeader *icmp;

    icmp = (struct ICMPHeader *) packet_buffer;

    memset(icmp, 0, sizeof(struct ICMPHeader));

    icmp->type = ICMP6_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(probe->sequence);

    return 0;
}

/*
    Set the port numbers for an outgoing UDP probe.
    There is limited space in the header for a sequence number
    to identify the probe upon return.

    We store the sequence number in the destination port, the local
    port, or the checksum.  The location chosen depends upon which
    probe parameters have been requested.
*/
static
void set_udp_ports(
    struct UDPHeader *udp,
    struct probe_t *probe,
    const struct probe_param_t *param)
{
    if (param->dest_port) {
        udp->dstport = htons(param->dest_port);

        if (param->local_port) {
            udp->srcport = htons(param->local_port);
            udp->checksum = htons(probe->sequence);
        } else {
            udp->srcport = htons(probe->sequence);
            udp->checksum = 0;
        }
    } else {
        udp->dstport = htons(probe->sequence);

        if (param->local_port) {
            udp->srcport = htons(param->local_port);
        } else {
            udp->srcport = htons(getpid());
        }

        udp->checksum = 0;
    }
    *sockaddr_port_offset(&probe->local_addr) = udp->srcport;
    *sockaddr_port_offset(&probe->remote_addr) = udp->dstport;
}

/* Prepend pseudoheader to the udp datagram and calculate checksum */
static
int udp4_checksum(void *pheader, void *udata, int psize, int dsize,
                  int alt_checksum)
{
    unsigned int totalsize = psize + dsize;
    unsigned char csumpacket[totalsize];

    memcpy(csumpacket, pheader, psize); /* pseudo header */
    memcpy(csumpacket+psize, udata, dsize);   /* udp header & payload */

    if (alt_checksum && dsize >= sizeof(struct UDPHeader) + 2) {
        csumpacket[psize + sizeof(struct UDPHeader)] = 0;
        csumpacket[psize + sizeof(struct UDPHeader) + 1] = 0;
    }

    return compute_checksum(csumpacket, totalsize);
}

/*
    Construct a header for UDP probes, using the port number associated
    with the probe.
*/
static
void construct_udp4_header(
    const struct net_state_t *net_state,
    struct probe_t *probe,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct UDPHeader *udp;
    int udp_size;

    if (net_state->platform.ip4_socket_raw) {
        udp = (struct UDPHeader *) &packet_buffer[sizeof(struct IPHeader)];
        udp_size = packet_size - sizeof(struct IPHeader);
    } else {
        udp = (struct UDPHeader *) &packet_buffer[0];
        udp_size = packet_size;
    }

    memset(udp, 0, sizeof(struct UDPHeader));

    set_udp_ports(udp, probe, param);
    udp->length = htons(udp_size);

    /* calculate udp checksum */
    struct UDPPseudoHeader udph = {
        .saddr = *(uint32_t *)sockaddr_addr_offset(&probe->local_addr),
        .daddr = *(uint32_t *)sockaddr_addr_offset(&probe->remote_addr),
        .zero = 0,
        .protocol = 17,
        .len = udp->length
    };

    /* get position to write checksum */
    uint16_t *checksum_off = &udp->checksum;

    if (udp->checksum != 0)
    { /* checksum is sequence number - correct the payload to match the checksum
         checksum_off is udp payload */
        checksum_off = (uint16_t *)&packet_buffer[packet_size -
                                                  udp_size +
                                                  sizeof(struct UDPHeader)];
    }
    *checksum_off = htons(udp4_checksum(&udph, udp,
                                        sizeof(struct UDPPseudoHeader),
                                        udp_size, udp->checksum != 0));
}

/*  Construct a header for UDPv6 probes  */
static
int construct_udp6_packet(
    const struct net_state_t *net_state,
    struct probe_t *probe,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    int udp_socket = net_state->platform.udp6_send_socket;
    struct UDPHeader *udp;
    int udp_size;

    udp = (struct UDPHeader *) packet_buffer;
    udp_size = packet_size;

    memset(udp, 0, sizeof(struct UDPHeader));

    set_udp_ports(udp, probe, param);
    udp->length = htons(udp_size);

    struct IP6PseudoHeader udph = {
        .zero = {0,0,0},
        .protocol = 17,
        .len = udp->length
    };
    memcpy(udph.saddr, sockaddr_addr_offset(&probe->local_addr), 16);
    memcpy(udph.daddr, sockaddr_addr_offset(&probe->remote_addr), 16);

    /* get position to write checksum */
    uint16_t *checksum_off = &udp->checksum;

    if (udp->checksum != 0)
    { /* checksum is sequence number - correct the payload to match the checksum
         checksum_off is udp payload */
        checksum_off = (uint16_t *)&packet_buffer[sizeof(struct UDPHeader)];
    }
    *checksum_off = htons(udp4_checksum(&udph, udp,
                                        sizeof(struct IP6PseudoHeader),
                                        udp_size, udp->checksum != 0));
    return 0;
}

/*
    Set the socket options for an outgoing stream protocol socket based on
    the packet parameters.
*/
static
int set_stream_socket_options(
    int stream_socket,
    const struct probe_param_t *param)
{
    int level;
    int opt;
    int reuse = 1;

    /*  Allow binding to a local port previously in use  */
#ifdef SO_REUSEPORT
    /*
       FreeBSD wants SO_REUSEPORT in addition to SO_REUSEADDR to
       bind to the same port
     */
    if (setsockopt(stream_socket, SOL_SOCKET, SO_REUSEPORT,
                   &reuse, sizeof(int)) == -1) {

        return -1;
    }
#endif

    if (setsockopt(stream_socket, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(int)) == -1) {

        return -1;
    }

    /*  Set the number of hops the probe will transit across  */
    if (param->ip_version == 6) {
        level = IPPROTO_IPV6;
        opt = IPV6_UNICAST_HOPS;
    } else {
        level = IPPROTO_IP;
        opt = IP_TTL;
    }

    if (setsockopt(stream_socket, level, opt, &param->ttl, sizeof(int)) ==
        -1) {

        return -1;
    }

    /*  Set the "type of service" field of the IP header  */
    if (param->ip_version == 6) {
        level = IPPROTO_IPV6;
        opt = IPV6_TCLASS;
    } else {
        level = IPPROTO_IP;
        opt = IP_TOS;
    }

    if (setsockopt(stream_socket, level, opt,
                   &param->type_of_service, sizeof(int)) == -1) {

        return -1;
    }
#ifdef SO_MARK
    if (param->routing_mark) {
        if (setsockopt(stream_socket, SOL_SOCKET,
                       SO_MARK, &param->routing_mark, sizeof(int))) {
            return -1;
        }
    }
#endif

#ifdef SO_BINDTODEVICE
    if (param->local_device) {
        if (setsockopt(stream_socket, SOL_SOCKET,
                       SO_BINDTODEVICE, param->local_device, strlen(param->local_device))) {
            return -1;
        }
    }
#endif

    return 0;
}

/*
    Open a TCP or SCTP socket, respecting the probe paramters as much as
    we can, and use it as an outgoing probe.
*/
static
int open_stream_socket(
    const struct net_state_t *net_state,
    int protocol,
    int port,
    const struct sockaddr_storage *src_sockaddr,
    const struct sockaddr_storage *dest_sockaddr,
    const struct probe_param_t *param)
{
    int stream_socket;
    int addr_len;
    int dest_port;
    struct sockaddr_storage dest_port_addr;
    struct sockaddr_storage src_port_addr;

    if (param->ip_version == 6) {
        stream_socket = socket(AF_INET6, SOCK_STREAM, protocol);
        addr_len = sizeof(struct sockaddr_in6);
    } else if (param->ip_version == 4) {
        stream_socket = socket(AF_INET, SOCK_STREAM, protocol);
        addr_len = sizeof(struct sockaddr_in);
    } else {
        errno = EINVAL;
        return -1;
    }

    if (stream_socket == -1) {
        return -1;
    }

    set_socket_nonblocking(stream_socket);

    if (set_stream_socket_options(stream_socket, param)) {
        close(stream_socket);
        return -1;
    }

    /*
       Bind to a known local port so we can identify which probe
       causes a TTL expiration.
     */
    construct_addr_port(&src_port_addr, src_sockaddr, port);
    if (bind(stream_socket, (struct sockaddr *) &src_port_addr, addr_len)) {
        close(stream_socket);
        return -1;
    }

    if (param->dest_port) {
        dest_port = param->dest_port;
    } else {
        /*  Use http if no port is specified  */
        dest_port = HTTP_PORT;
    }

    /*  Attempt a connection  */
    construct_addr_port(&dest_port_addr, dest_sockaddr, dest_port);
    if (connect
        (stream_socket, (struct sockaddr *) &dest_port_addr, addr_len)) {

        /*  EINPROGRESS simply means the connection is in progress  */
        if (errno != EINPROGRESS) {
            close(stream_socket);
            return -1;
        }
    }

    return stream_socket;
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

    if (param->protocol == IPPROTO_TCP) {
        return 0;
    }
#ifdef IPPROTO_SCTP
    if (param->protocol == IPPROTO_SCTP) {
        return 0;
    }
#endif

    /*  Start by determining the full size, including omitted headers  */
    if (param->ip_version == 6) {
        if (net_state->platform.ip6_socket_raw) {
            packet_size += sizeof(struct IP6Header);
        }
    } else if (param->ip_version == 4) {
        if (net_state->platform.ip4_socket_raw) {
            packet_size += sizeof(struct IPHeader);
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    if (param->protocol == IPPROTO_ICMP) {
        packet_size += sizeof(struct ICMPHeader);
    } else if (param->protocol == IPPROTO_UDP) {
        packet_size += sizeof(struct UDPHeader);

        /*  We may need to put the sequence number in the payload  */
        packet_size += sizeof(int);
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
    if (param->ip_version == 6 && net_state->platform.ip6_socket_raw) {
        packet_size -= sizeof(struct IP6Header);
    }

    return packet_size;
}

/*  Construct a packet for an IPv4 probe  */
static
int construct_ip4_packet(
    const struct net_state_t *net_state,
    int *packet_socket,
    struct probe_t *probe,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    int send_socket = net_state->platform.ip4_send_socket;
    bool is_stream_protocol = false;
    int tos, ttl, socket;
    bool bind_send_socket = false;
    struct sockaddr_storage current_sockaddr;
    int current_sockaddr_len;

    if (param->protocol == IPPROTO_TCP) {
        is_stream_protocol = true;
#ifdef IPPROTO_SCTP
    } else if (param->protocol == IPPROTO_SCTP) {
        is_stream_protocol = true;
#endif
    } else {
        if (net_state->platform.ip4_socket_raw) {
            construct_ip4_header(net_state, probe, packet_buffer, packet_size,
                                  param);
        }
        if (param->protocol == IPPROTO_ICMP) {
            construct_icmp4_header(net_state, probe, packet_buffer,
                                   packet_size, param);
        } else if (param->protocol == IPPROTO_UDP) {
            construct_udp4_header(net_state, probe, packet_buffer,
                                  packet_size, param);
        } else {
            errno = EINVAL;
            return -1;
        }
    }

    if (is_stream_protocol) {
        send_socket =
            open_stream_socket(net_state, param->protocol, probe->sequence,
                               &probe->local_addr, &probe->remote_addr, param);

        if (send_socket == -1) {
            return -1;
        }

        *packet_socket = send_socket;
        return 0;
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
        if (setsockopt(send_socket, SOL_SOCKET,
                       SO_MARK, &param->routing_mark, sizeof(int))) {
            return -1;
        }
    }
#endif

#ifdef SO_BINDTODEVICE
    if (param->local_device) {
        if (setsockopt(send_socket, SOL_SOCKET,
                       SO_BINDTODEVICE, param->local_device, strlen(param->local_device))) {
            return -1;
        }
    }
#endif

    /*
       Bind src port when not using raw socket to pass in ICMP id, kernel
       get ICMP id from src_port when using DGRAM socket.
     */
    if (!net_state->platform.ip4_socket_raw &&
            param->protocol == IPPROTO_ICMP &&
            !param->is_probing_byte_order) {
        current_sockaddr_len = sizeof(struct sockaddr_in);
        bind_send_socket = true;
        socket = net_state->platform.ip4_txrx_icmp_socket;
        if (getsockname(socket, (struct sockaddr *) &current_sockaddr,
                        &current_sockaddr_len)) {
            return -1;
        }
        struct sockaddr_in *sin_cur =
            (struct sockaddr_in *) &current_sockaddr;

        /* avoid double bind */
        if (sin_cur->sin_port) {
            bind_send_socket = false;
        }
    }

    /*  Bind to our local address  */
    if (bind_send_socket && bind(socket, (struct sockaddr *)&probe->local_addr,
                sizeof(struct sockaddr_in))) {
        return -1;
    }

    /* set TOS and TTL for non-raw socket */
    if (!net_state->platform.ip4_socket_raw && !param->is_probing_byte_order) {
        if (param->protocol == IPPROTO_ICMP) {
            socket = net_state->platform.ip4_txrx_icmp_socket;
        } else if (param->protocol == IPPROTO_UDP) {
            socket = net_state->platform.ip4_txrx_udp_socket;
        } else {
            return 0;
        }
        tos = param->type_of_service;
        if (setsockopt(socket, SOL_IP, IP_TOS, &tos, sizeof(int))) {
            return -1;
        }
        ttl = param->ttl;
        if (setsockopt(socket, SOL_IP, IP_TTL,
                       &ttl, sizeof(int)) == -1) {
            return -1;
        }
    }

    return 0;
}

/*  Construct a packet for an IPv6 probe  */
static
int construct_ip6_packet(
    const struct net_state_t *net_state,
    int *packet_socket,
    struct probe_t *probe,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    int send_socket;
    bool is_stream_protocol = false;
    bool bind_send_socket = true;
    struct sockaddr_storage current_sockaddr;
    int current_sockaddr_len;

    if (param->protocol == IPPROTO_TCP) {
        is_stream_protocol = true;
#ifdef IPPROTO_SCTP
    } else if (param->protocol == IPPROTO_SCTP) {
        is_stream_protocol = true;
#endif
    } else if (param->protocol == IPPROTO_ICMP) {
        if (net_state->platform.ip6_socket_raw) {
            send_socket = net_state->platform.icmp6_send_socket;
        } else {
            send_socket = net_state->platform.ip6_txrx_icmp_socket;
        }

        if (construct_icmp6_packet
            (net_state, probe, packet_buffer, packet_size, param)) {
            return -1;
        }
    } else if (param->protocol == IPPROTO_UDP) {
        if (net_state->platform.ip6_socket_raw) {
            send_socket = net_state->platform.udp6_send_socket;
        } else {
            send_socket = net_state->platform.ip6_txrx_udp_socket;
        }

        if (construct_udp6_packet
            (net_state, probe, packet_buffer, packet_size, param)) {
            return -1;
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    if (is_stream_protocol) {
        send_socket =
            open_stream_socket(net_state, param->protocol, probe->sequence,
                               &probe->local_addr, &probe->remote_addr, param);

        if (send_socket == -1) {
            return -1;
        }

        *packet_socket = send_socket;
        return 0;
    }

    /*
       Check the current socket address, and if it is the same
       as the source address we intend, we will skip the bind.
       This is to accommodate Solaris, which, as of Solaris 11.3,
       will return an EINVAL error on bind if the socket is already
       bound, even if the same address is used.
     */
    current_sockaddr_len = sizeof(struct sockaddr_in6);
    if (getsockname(send_socket, (struct sockaddr *) &current_sockaddr,
                    &current_sockaddr_len) == 0) {
        struct sockaddr_in6 *sin6_cur = (struct sockaddr_in6 *) &current_sockaddr;

        if (net_state->platform.ip6_socket_raw) {
            if (memcmp(&current_sockaddr,
                       &probe->local_addr, sizeof(struct sockaddr_in6)) == 0) {
                bind_send_socket = false;
            }
        } else {
            /* avoid double bind for DGRAM socket */
            if (sin6_cur->sin6_port) {
                bind_send_socket = false;
            }
        }
    }

    /*  Bind to our local address  */
    if (bind_send_socket) {
        if (bind(send_socket, (struct sockaddr *) &probe->local_addr,
                 sizeof(struct sockaddr_in6))) {
            return -1;
        }
    }

    /*  The traffic class in IPv6 is analogous to ToS in IPv4  */
    if (setsockopt(send_socket, IPPROTO_IPV6,
                   IPV6_TCLASS, &param->type_of_service, sizeof(int))) {
        return -1;
    }

    /*  Set the time-to-live  */
    if (setsockopt(send_socket, IPPROTO_IPV6,
                   IPV6_UNICAST_HOPS, &param->ttl, sizeof(int))) {
        return -1;
    }
#ifdef SO_MARK
    if (param->routing_mark) {
        if (setsockopt(send_socket,
                       SOL_SOCKET, SO_MARK, &param->routing_mark,
                       sizeof(int))) {
            return -1;
        }
    }
#endif

#ifdef SO_BINDTODEVICE
    if (param->local_device) {
        if (setsockopt(send_socket,
                       SOL_SOCKET, SO_BINDTODEVICE, param->local_device,
                       strlen(param->local_device))) {
            return -1;
        }
    }
#endif

    return 0;
}

/*  Construct a probe packet based on the probe parameters  */
int construct_packet(
    const struct net_state_t *net_state,
    int *packet_socket,
    struct probe_t *probe,
    char *packet_buffer,
    int packet_buffer_size,
    const struct probe_param_t *param)
{
    int packet_size;

    packet_size = compute_packet_size(net_state, param);
    if (packet_size < 0) {
        return -1;
    }

    if (packet_buffer_size < packet_size) {
        errno = EINVAL;
        return -1;
    }

    memset(packet_buffer, param->bit_pattern, packet_size);

    if (param->ip_version == 6) {
        if (construct_ip6_packet(net_state, packet_socket, probe,
                                 packet_buffer, packet_size,
                                 param)) {
            return -1;
        }
    } else if (param->ip_version == 4) {
        if (construct_ip4_packet(net_state, packet_socket, probe,
                                 packet_buffer, packet_size,
                                 param)) {
            return -1;
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    return packet_size;
}
