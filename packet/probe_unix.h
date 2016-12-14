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

#ifndef PROBE_UNIX_H
#define PROBE_UNIX_H

/*  We need to track the transmission and timeouts on Unix systems  */
struct probe_platform_t
{
    /*  The time at which the probe is considered lost  */
    struct timeval timeout_time;

    /*  The time at which the probe was sent  */
    struct timeval departure_time;

};

/*  We'll use rack sockets to send and recieve probes on Unix systems  */
struct net_state_platform_t
{
    /*  Socket used to send raw IPv4 packets  */
    int ip4_send_socket;

    /*  Socket used to receive IPv4 ICMP replies  */
    int ip4_recv_socket;

    /*  Send socket for ICMPv6 packets  */
    int icmp6_send_socket;

    /*  Send socket for UDPv6 packets  */
    int udp6_send_socket;

    /*  Receive socket for IPv6 packets  */
    int ip6_recv_socket;

    /*
        true if we should encode the IP header length in host order.
        (as opposed to network order)
    */
    bool ip_length_host_order;
};

#endif
