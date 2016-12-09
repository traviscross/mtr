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

#include <stdio.h>
#include <winternl.h>

#include "protocols.h"

/*  Windows doesn't require any initialization at a privileged level  */
void init_net_state_privileged(
    struct net_state_t *net_state)
{
}

/*  Open the ICMP.DLL interface  */
void init_net_state(
    struct net_state_t *net_state)
{
    memset(net_state, 0, sizeof(struct net_state_t));

    net_state->platform.icmp4 = IcmpCreateFile();
    if (net_state->platform.icmp4 == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failure opening ICMPv4 %d\n", GetLastError());
        exit(1);
    }

    net_state->platform.icmp6 = Icmp6CreateFile();
    if (net_state->platform.icmp6 == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failure opening ICMPv6 %d\n", GetLastError());
        exit(1);
    }
}

/*
    The overlapped I/O style completion routine to be called by
    Windows during an altertable wait when an ICMP probe has
    completed, either by reply, or by ICMP.DLL timeout.
*/
static
void WINAPI on_icmp_reply(
    PVOID context,
    PIO_STATUS_BLOCK status,
    ULONG reserved)
{
    struct probe_t *probe = (struct probe_t *)context;
    int icmp_type;
    int round_trip_us = 0;
    int reply_count;
    int reply_status = 0;
    int err;
    struct sockaddr_storage remote_addr;
    struct sockaddr_in *remote_addr4;
    struct sockaddr_in6 *remote_addr6;
    ICMP_ECHO_REPLY32 *reply4;
    ICMPV6_ECHO_REPLY *reply6;

    if (probe->platform.ip_version == 6) {
        reply6 = &probe->platform.reply6;
        reply_count = Icmp6ParseReplies(reply6, sizeof(ICMPV6_ECHO_REPLY));

        if (reply_count > 0) {
            reply_status = reply6->Status;

            /*  Unfortunately, ICMP.DLL only has millisecond precision  */
            round_trip_us = reply6->RoundTripTime * 1000;

            remote_addr6 = (struct sockaddr_in6 *)&remote_addr;
            remote_addr6->sin6_family = AF_INET6;
            remote_addr6->sin6_port = 0;
            remote_addr6->sin6_flowinfo = 0;
            memcpy(
                &remote_addr6->sin6_addr, reply6->AddressBits,
                sizeof(struct in6_addr));
            remote_addr6->sin6_scope_id = 0;
        }
    } else {
        reply4 = &probe->platform.reply4;
        reply_count = IcmpParseReplies(reply4, sizeof(ICMP_ECHO_REPLY));

        if (reply_count > 0) {
            reply_status = reply4->Status;

            /*  Unfortunately, ICMP.DLL only has millisecond precision  */
            round_trip_us = reply4->RoundTripTime * 1000;

            remote_addr4 = (struct sockaddr_in *)&remote_addr;
            remote_addr4->sin_family = AF_INET;
            remote_addr4->sin_port = 0;
            remote_addr4->sin_addr.s_addr = reply4->Address;
        }
    }

    if (reply_count == 0) {
        err = GetLastError();

        /*  It could be that we got no reply because of timeout  */
        if (err == IP_REQ_TIMED_OUT) {
            printf("%d no-reply\n", probe->token);

            free_probe(probe);
            return;
        }

        fprintf(stderr, "IcmpParseReplies failure %d\n", err);
        exit(1);
    }


    icmp_type = -1;
    if (reply_status == IP_SUCCESS) {
        icmp_type = ICMP_ECHOREPLY;
    } else if (reply_status == IP_TTL_EXPIRED_TRANSIT) {
        icmp_type = ICMP_TIME_EXCEEDED;
    }

    if (icmp_type != -1) {
        /*  Record probe result  */
        respond_to_probe(probe, icmp_type, &remote_addr, round_trip_us);
    } else {
        fprintf(stderr, "Unexpected ICMP result %d\n", icmp_type);
    }
}

/*  Send a new probe using ICMP.DLL's send echo mechanism  */
void send_probe(
    struct net_state_t *net_state,
    const struct probe_param_t *param)
{
    IP_OPTION_INFORMATION option;
    DWORD send_result;
    DWORD timeout;
    struct probe_t *probe;
    struct sockaddr_storage dest_sockaddr;
    struct sockaddr_storage src_sockaddr;
    struct sockaddr_in *dest_sockaddr4;
    struct sockaddr_in6 *src_sockaddr6;
    struct sockaddr_in6 *dest_sockaddr6;

    if (decode_dest_addr(param, &dest_sockaddr)) {
        printf("%d invalid-argument\n", param->command_token);
        return;
    }

    if (param->timeout > 0) {
        timeout = 1000 * param->timeout;
    } else {
        /*
            IcmpSendEcho2 will return invalid argument on a timeout of 
            zero.  Our Unix implementation allows it.  Bump up the timeout
            to 1 millisecond.
        */
        timeout = 1;
    }

    probe = alloc_probe(net_state, param->command_token);
    if (probe == NULL) {
        printf("%d probes-exhausted\n", param->command_token);
        return;
    }

    if (find_source_addr(&src_sockaddr, &dest_sockaddr)) {
        fprintf(stderr, "error finding source address\n");
        exit(1);
    }

    probe->platform.ip_version = param->ip_version;

    memset(&option, 0, sizeof(IP_OPTION_INFORMATION32));
    option.Ttl = param->ttl;

    if (param->ip_version == 6) {
        src_sockaddr6 = (struct sockaddr_in6 *)&src_sockaddr;
        dest_sockaddr6 = (struct sockaddr_in6 *)&dest_sockaddr;

        send_result = Icmp6SendEcho2(
            net_state->platform.icmp6, NULL,
            (FARPROC)on_icmp_reply, probe,
            src_sockaddr6, dest_sockaddr6, NULL, 0, &option,
            &probe->platform.reply6, sizeof(ICMPV6_ECHO_REPLY), timeout);
    } else {
        dest_sockaddr4 = (struct sockaddr_in *)&dest_sockaddr;
        send_result = IcmpSendEcho2(
            net_state->platform.icmp4, NULL,
            (FARPROC)on_icmp_reply, probe,
            dest_sockaddr4->sin_addr.s_addr, NULL, 0, &option,
            &probe->platform.reply4, sizeof(ICMP_ECHO_REPLY), timeout);
    }

    if (send_result == 0) {
        /*
            ERROR_IO_PENDING is expected for asynchronous probes,
            but any other error is unexpected.
        */
        if (GetLastError() != ERROR_IO_PENDING) {
            fprintf(stderr, "IcmpSendEcho2 failure %d\n", GetLastError());
            exit(1);
        }
    }
}

/*
    On Windows, an implementation of receive_replies is unnecessary, because,
    unlike Unix, replies are completed using Overlapped I/O during an
    alertable wait, and don't require explicit reads.
*/
void receive_replies(
    struct net_state_t *net_state)
{
}

/*
    On Windows, an implementation of check_probe_timeout is unnecesary because
    timeouts are managed by ICMP.DLL, including a call to the I/O completion
    routine when the time fully expires.
*/
void check_probe_timeouts(
    struct net_state_t *net_state)
{
}

/*
    As in the case of check_probe_timeout, getting the next probe timeout is
    unnecessary under Windows, as ICMP.DLL manages timeouts for us.
*/
bool get_next_probe_timeout(
    const struct net_state_t *net_state,
    struct timeval *timeout)
{
    return false;
}
