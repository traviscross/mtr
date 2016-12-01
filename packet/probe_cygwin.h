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

#ifndef PROBE_CYGWIN_H
#define PROBE_CYGWIN_H

#include <arpa/inet.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

/*
	Windows requires an echo reply structure for each in-flight
	ICMP probe.
*/
struct probe_platform_t
{
    ICMP_ECHO_REPLY32 reply;
};

/*  A Windows HANDLE for the ICMP session  */
struct net_state_platform_t
{
    HANDLE icmp;
};

#endif
