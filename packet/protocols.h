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

#ifndef PROTOCOLS_H
#define PROTOCOLS_H

/*  ICMP type codes  */
#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_ECHO 8
#define ICMP_TIME_EXCEEDED 11

/*  We can't rely on header files to provide this information, because
    the fields have different names between, for instance, Linux and 
    Solaris  */
struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

/* Structure of an UDP header.  */
struct UDPHeader {
    uint16_t srcport;
    uint16_t dstport;
    uint16_t length;
    uint16_t checksum;
};

/* Structure of an TCP header, as far as we need it.  */
struct TCPHeader {
    uint16_t srcport;
    uint16_t dstport;
    uint32_t seq;
};

/* Structure of an SCTP header */
struct SCTPHeader {
    uint16_t srcport;
    uint16_t dstport;
    uint32_t veri_tag;
};

/* Structure of an IPv4 UDP pseudoheader.  */
struct UDPv4PHeader {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

/*  Structure of an IP header.  */
struct IPHeader {
    uint8_t version;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

#endif
