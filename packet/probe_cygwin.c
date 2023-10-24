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

#include "probe.h"

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <unistd.h>
#include <winternl.h>

#include "protocols.h"


/*
    Implementation notes  (or "Why this uses a worker thread")

    Having done my time debugging various race conditions over the
    last twenty-plus years as a software developer, both of my own
    creation and discovered in the code of others, I almost always
    try to structure my code to be single-threaded.  However,
    I think in this case, the ICMP service thread is unavoidable.

    I would have liked to avoid multithreading entirely, but here are
    the constraints:

        a)  mtr was originally a Unix program which used "raw sockets".
        b)  In order to port mtr to Windows, Cygwin is used to get a
            Unix-like environment.
        c)  You can't use a raw socket to receive an ICMP reply on Windows.
            However, Windows provides a separate API in the form of
            ICMP.DLL for sending and receiving ICMP messages.
        d)  The ICMP API works asynchronously, and requires completion
            through an asynchronous procedure call ("APC")
        e)  APCs are only delivered during blocking Win32 operations
            which are flagged as "alertable."  This prevents apps from
            having APCs execute unexpectedly during an I/O operation.
        f)  Cygwin's implementation of POSIX functions does all I/O
            through non-alertable I/O operations.  This is reasonable
            because APCs don't exist in the POSIX API.
        g)  Cygwin implements Unix-style signals at the application level,
            since the Windows kernel doesn't have them.  We want our
            program to respond to SIGTERM and SIGKILL, at least.
        h)  Cygwin's signal implementation will deliver signals during
            blocking I/O functions in the Cygwin library, but won't
            respond to signals if the signal is sent while the application
            is in a blocking Windows API call which Cygwin is not aware of.
        i)  Since we want to both send/receive ICMP probes and also respond
            to Unix-style signals, we require two threads:  one which
            uses Cygwin's POSIX style blocking I/O and can respond to
            signals, and one which uses alertable waits using Win32
            blocking APIs.

    The solution is to have the main thread using select() as the
    blocking operation in its loop, and also to have an ICMP service
    thread using WaitForSingleObjectEx() as its blocking operation.
    The main thread will respond to signals.  The ICMP service thread
    will run the APCs completing ICMP.DLL requests.

    These two threads communicate through a pair of pipes.  One pipe
    sends requests from the main thread to the ICMP service thread,
    and another pipe sends the requests back as they complete.

    We use the Cygwin pipe() to create the pipes, but in the ICMP
    service thread we use the Win32 HANDLE that corresponds to the
    receiving end of the input pipe to wait for ICMP requests.
*/


static DWORD WINAPI icmp_service_thread(LPVOID param);

/*  Windows doesn't require any initialization at a privileged level  */
void init_net_state_privileged(
    struct net_state_t *net_state)
{
}

/*
    Convenience similar to error(), but for reporting Windows
    error codes instead of errno codes.
*/
void error_win(int exit_code, int win_error, const char *str) {
    fprintf(stderr, "%s (code %d)\n", str, win_error);
    exit(exit_code);
}

/*  Open the ICMP.DLL interface and start the ICMP service thread  */
void init_net_state(
    struct net_state_t *net_state)
{
    HANDLE thread;
    int in_pipe[2], out_pipe[2];
    int err;

    memset(net_state, 0, sizeof(struct net_state_t));

    net_state->platform.icmp4 = IcmpCreateFile();
    net_state->platform.icmp6 = Icmp6CreateFile();

    if (net_state->platform.icmp4 == INVALID_HANDLE_VALUE
        && net_state->platform.icmp6 == INVALID_HANDLE_VALUE) {

        error_win(EXIT_FAILURE, GetLastError(), "Failure opening ICMP");
    }
    net_state->platform.ip4_socket_raw = false;
    net_state->platform.ip6_socket_raw = false;

    /*
        We need a pipe for communication with the ICMP thread
        in each direction.
    */
    if (pipe(in_pipe) == -1 || pipe(out_pipe) == -1) {
        error(EXIT_FAILURE, errno, "Failure creating thread pipe");
    }

    net_state->platform.thread_in_pipe_read = in_pipe[0];
    net_state->platform.thread_in_pipe_write = in_pipe[1];
    net_state->platform.thread_out_pipe_read = out_pipe[0];
    net_state->platform.thread_out_pipe_write = out_pipe[1];

    InitializeCriticalSection(&net_state->platform.pending_request_cs);
    net_state->platform.pending_request_count = 0;
    net_state->platform.pending_request_event =
        CreateEvent(NULL, TRUE, FALSE, NULL);

    if (net_state->platform.pending_request_event == NULL) {
        error(EXIT_FAILURE, errno, "Failure creating request event");
    }

    /*
        The read on the out pipe needs to be nonblocking because
        it will be occasionally checked in the main thread.
    */
    err = fcntl(out_pipe[0], F_SETFL, O_NONBLOCK);
    if (err == -1) {
        error(
            EXIT_FAILURE, errno,
            "Failure setting pipe to non-blocking");
    }

    /*  Spin up the ICMP service thread  */
    thread = CreateThread(
        NULL, 0, icmp_service_thread, net_state, 0, NULL);

    if (thread == NULL) {
        error_win(
            EXIT_FAILURE, GetLastError(),
            "Failure creating ICMP service thread");
    }
}

/*
    If we succeeded at opening the ICMP file handle, we can
    assume that IP protocol version is supported.
*/
bool is_ip_version_supported(
    struct net_state_t *net_state,
    int ip_version)
{
    if (ip_version == 4) {
        return (net_state->platform.icmp4 != INVALID_HANDLE_VALUE);
    } else if (ip_version == 6) {
        return (net_state->platform.icmp6 != INVALID_HANDLE_VALUE);
    }

    return false;
}

/*  On Windows, we only support ICMP probes  */
bool is_protocol_supported(
    struct net_state_t * net_state,
    int protocol)
{
    if (protocol == IPPROTO_ICMP) {
        return true;
    }

    return false;
}

/*  Set the back pointer to the net_state when a probe is allocated  */
void platform_alloc_probe(
    struct net_state_t *net_state,
    struct probe_t *probe)
{
    probe->platform.net_state = net_state;
}

/*  Free the reply buffer when the probe is freed  */
void platform_free_probe(
    struct probe_t *probe)
{
}

/*  Report a windows error code using a platform-independent error string  */
static
void report_win_error(
    int command_token,
    int err)
{
    /*  It could be that we got no reply because of timeout  */
    if (err == IP_REQ_TIMED_OUT || err == IP_SOURCE_QUENCH) {
        printf("%d no-reply\n", command_token);
    } else if (err == ERROR_INVALID_NETNAME) {
        printf("%d address-not-available\n", command_token);
    } else if (err == ERROR_INVALID_PARAMETER) {
        printf("%d invalid-argument\n", command_token);
    } else {
        printf("%d unexpected-error winerror %d\n", command_token, err);
    }
}

/*
    After we have the result of an ICMP probe on the ICMP service
    thread, this is used to send the result back to the main thread
    for probe result reporting.
*/
static
void queue_thread_result(struct icmp_thread_request_t *request)
{
    int byte_count;

    /*  Pass ownership of the request back through the result pipe  */
    byte_count = write(
        request->net_state->platform.thread_out_pipe_write,
        &request,
        sizeof(struct icmp_thread_request_t *));
    if (byte_count == -1) {
        error(
            EXIT_FAILURE, errno,
            "failure writing to probe result queue");
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
    struct icmp_thread_request_t *request =
        (struct icmp_thread_request_t *) context;
    int icmp_type;
    int round_trip_us = 0;
    int reply_count;
    int reply_status = 0;
    struct sockaddr_storage remote_addr;
    struct sockaddr_in *remote_addr4;
    struct sockaddr_in6 *remote_addr6;
    ICMP_ECHO_REPLY *reply4;
    ICMPV6_ECHO_REPLY *reply6;

    if (request->ip_version == 6) {
        reply6 = request->reply6;
        reply_count = Icmp6ParseReplies(reply6, sizeof(ICMPV6_ECHO_REPLY));

        if (reply_count > 0) {
            reply_status = reply6->Status;

            /*  Unfortunately, ICMP.DLL only has millisecond precision  */
            round_trip_us = reply6->RoundTripTime * 1000;

            remote_addr6 = (struct sockaddr_in6 *) &remote_addr;
            remote_addr6->sin6_family = AF_INET6;
            remote_addr6->sin6_port = 0;
            remote_addr6->sin6_flowinfo = 0;
            memcpy(&remote_addr6->sin6_addr, reply6->Address.sin6_addr,
                   sizeof(struct in6_addr));
            remote_addr6->sin6_scope_id = 0;
        }
    } else {
        reply4 = request->reply4;
        reply_count = IcmpParseReplies(reply4, sizeof(ICMP_ECHO_REPLY));

        if (reply_count > 0) {
            reply_status = reply4->Status;

            /*  Unfortunately, ICMP.DLL only has millisecond precision  */
            round_trip_us = reply4->RoundTripTime * 1000;

            remote_addr4 = (struct sockaddr_in *) &remote_addr;
            remote_addr4->sin_family = AF_INET;
            remote_addr4->sin_port = 0;
            remote_addr4->sin_addr.s_addr = reply4->Address;
        }
    }

    if (reply_count == 0) {
        reply_status = GetLastError();
    }

    icmp_type = -1;
    if (reply_status == IP_SUCCESS) {
        icmp_type = ICMP_ECHOREPLY;
    } else if (reply_status == IP_TTL_EXPIRED_TRANSIT
               || reply_status == IP_TTL_EXPIRED_REASSEM) {

        icmp_type = ICMP_TIME_EXCEEDED;
    } else if (reply_status == IP_DEST_HOST_UNREACHABLE
               || reply_status == IP_DEST_PORT_UNREACHABLE
               || reply_status == IP_DEST_PROT_UNREACHABLE
               || reply_status == IP_DEST_NET_UNREACHABLE
               || reply_status == IP_DEST_UNREACHABLE
               || reply_status == IP_DEST_NO_ROUTE
               || reply_status == IP_BAD_ROUTE
               || reply_status == IP_BAD_DESTINATION) {

        icmp_type = ICMP_DEST_UNREACH;
    }

    request->icmp_type = icmp_type;
    request->reply_status = reply_status;
    request->remote_addr = remote_addr;
    request->round_trip_us = round_trip_us;
    queue_thread_result(request);
}

/*  Use ICMP.DLL's send echo support to send a probe  */
static
void icmp_send_probe(
    struct icmp_thread_request_t *request,
    char *payload,
    int payload_size)
{
    IP_OPTION_INFORMATION option;
    DWORD timeout;
    DWORD send_result;
    int reply_size;
    int err;
    struct sockaddr_in *dest_sockaddr4;
    struct sockaddr_in6 *src_sockaddr6;
    struct sockaddr_in6 *dest_sockaddr6;

    if (request->timeout > 0) {
        timeout = 1000 * request->timeout;
    } else {
        /*
           IcmpSendEcho2 will return invalid argument on a timeout of
           zero.  Our Unix implementation allows it.  Bump up the timeout
           to 1 millisecond.
         */
        timeout = 1;
    }

    memset(&option, 0, sizeof(IP_OPTION_INFORMATION));
    option.Ttl = request->ttl;

    if (request->ip_version == 6) {
        reply_size = sizeof(ICMPV6_ECHO_REPLY) + payload_size;
    } else {
        reply_size = sizeof(ICMP_ECHO_REPLY) + payload_size;
    }

    request->reply4 = malloc(reply_size);
    if (request->reply4 == NULL) {
        error(EXIT_FAILURE, errno, "failure to allocate reply buffer");
    }

    if (request->ip_version == 6) {
        src_sockaddr6 = (struct sockaddr_in6 *) &request->src_sockaddr;
        dest_sockaddr6 = (struct sockaddr_in6 *) &request->dest_sockaddr;

        send_result = Icmp6SendEcho2(request->net_state->platform.icmp6,
                                     NULL,
                                     (FARPROC) on_icmp_reply,
                                     request,
                                     src_sockaddr6, dest_sockaddr6,
                                     payload, payload_size, &option,
                                     request->reply6,
                                     reply_size, timeout);
    } else {
        dest_sockaddr4 = (struct sockaddr_in *) &request->dest_sockaddr;

        send_result = IcmpSendEcho2(request->net_state->platform.icmp4,
                                    NULL,
                                    (FARPROC) on_icmp_reply,
                                    request,
                                    dest_sockaddr4->sin_addr.s_addr,
                                    payload, payload_size, &option,
                                    request->reply4,
                                    reply_size, timeout);
    }

    if (send_result == 0) {
        err = GetLastError();

        /*
            ERROR_IO_PENDING is expected when the probe is sent.
            Other errors indicate the probe wasn't sent, and should
            be reported in the main thread.
        */
        if (err != ERROR_IO_PENDING) {
            request->icmp_type = -1;
            request->reply_status = err;
            queue_thread_result(request);
        }
    }
}

/*  Fill the payload of the packet as specified by the probe parameters  */
static
int fill_payload(
    const struct icmp_thread_request_t *request,
    char *payload,
    int payload_buffer_size)
{
    int ip_icmp_size;
    int payload_size;

    if (request->ip_version == 6) {
        ip_icmp_size =
            sizeof(struct IP6Header) + sizeof(struct ICMPHeader);
    } else if (request->ip_version == 4) {
        ip_icmp_size = sizeof(struct IPHeader) + sizeof(struct ICMPHeader);
    } else {
        errno = EINVAL;
        return -1;
    }

    payload_size = request->packet_size - ip_icmp_size;
    if (payload_size < 0) {
        payload_size = 0;
    }

    if (payload_size > payload_buffer_size) {
        errno = EINVAL;
        return -1;
    }

    memset(payload, request->bit_pattern, payload_size);

    return payload_size;
}

/*
    We've received a probe request from the main thread, so
    fill out a payload buffer and then send the probe.
*/
static
void icmp_handle_probe_request(struct icmp_thread_request_t *request)
{
    char payload[PACKET_BUFFER_SIZE];
    int payload_size;

    payload_size = fill_payload(request, payload, PACKET_BUFFER_SIZE);
    if (payload_size < 0) {
        error(EXIT_FAILURE, errno, "Error constructing packet");
    }

    icmp_send_probe(request, payload, payload_size);
}

/*
    Write the next thread request to the request pipe.
    Update the count of pending requests and set the event
    indicating that requests are present.
*/
static
void send_thread_request(
    struct net_state_t *net_state,
    struct icmp_thread_request_t *request)
{
    int byte_count;
    byte_count = write(
        net_state->platform.thread_in_pipe_write,
        &request,
        sizeof(struct icmp_thread_request_t *));

    if (byte_count == -1) {
        error(
            EXIT_FAILURE, errno,
            "failure writing to probe request queue");
    }

    EnterCriticalSection(&net_state->platform.pending_request_cs);
    {
        net_state->platform.pending_request_count++;
        SetEvent(net_state->platform.pending_request_event);
    }
    LeaveCriticalSection(&net_state->platform.pending_request_cs);
}

/*
    Read the next thread request from the pipe, if any are pending.
    If it is the last request in the queue, reset the pending
    request event.

    If no requests are pending, return NULL.
*/
static
struct icmp_thread_request_t *receive_thread_request(
    struct net_state_t *net_state)
{
    struct icmp_thread_request_t *request;
    int byte_count;
    bool pending_request;

    EnterCriticalSection(&net_state->platform.pending_request_cs);
    {
        if (net_state->platform.pending_request_count > 0) {
            pending_request = true;
            net_state->platform.pending_request_count--;
            if (net_state->platform.pending_request_count == 0) {
                ResetEvent(net_state->platform.pending_request_event);
            }
        } else {
            pending_request = false;
        }
    }
    LeaveCriticalSection(&net_state->platform.pending_request_cs);

    if (!pending_request) {
        return NULL;
    }

    byte_count = read(
        net_state->platform.thread_in_pipe_read,
        &request,
        sizeof(struct icmp_thread_request_t *));

    if (byte_count == -1) {
        error(
            EXIT_FAILURE,
            errno,
            "failure reading probe request queue");
    }

    assert(byte_count == sizeof(struct icmp_thread_request_t *));

    return request;
}

/*
    The main loop of the ICMP service thread.  The loop starts
    an overlapped read on the incoming request pipe, then waits
    in an alertable wait for that read to complete.  Because
    the wait is alertable, ICMP probes can complete through
    APCs in that wait.
*/
static
DWORD WINAPI icmp_service_thread(LPVOID param) {
    struct net_state_t *net_state;
    struct icmp_thread_request_t *request;

    net_state = (struct net_state_t *)param;
    while (true) {
        request = receive_thread_request(net_state);
        if (request != NULL) {
            /*  Start the new probe from the request  */
            icmp_handle_probe_request(request);
        } else {
            /*
                Wait for either a request to be queued or for
                an APC which completes an ICMP probe.
            */
            WaitForSingleObjectEx(
                net_state->platform.pending_request_event,
                INFINITE,
                TRUE);
        }
    }

    return 0;
}

/*
    When we are on the main thread and need the ICMP service thread
    to start a new probe, this is used to pass the request for the
    new probe to the service thread.
*/
static
void queue_thread_request(
    struct net_state_t *net_state,
    struct probe_t *probe,
    const struct probe_param_t *param,
    struct sockaddr_storage *dest_sockaddr,
    struct sockaddr_storage *src_sockaddr)
{
    struct icmp_thread_request_t *request;

    request = malloc(sizeof(struct icmp_thread_request_t));
    if (request == NULL) {
        error(EXIT_FAILURE, errno, "failure to allocate request");
    }
    memset(request, 0, sizeof(struct icmp_thread_request_t));

    request->ip_version = param->ip_version;
    request->ttl = param->ttl;
    request->timeout = param->timeout;
    request->packet_size = param->packet_size;
    request->bit_pattern = param->bit_pattern;

    request->net_state = net_state;
    request->probe = probe;
    request->dest_sockaddr = *dest_sockaddr;
    request->src_sockaddr = *src_sockaddr;

    /*
        The ownership of the request is passed to the ICMP thread
        through the pipe.
    */
    send_thread_request(net_state, request);
}

/*  Decode the probe parameters and send a probe  */
void send_probe(
    struct net_state_t *net_state,
    const struct probe_param_t *param)
{
    struct probe_t *probe;
    struct sockaddr_storage dest_sockaddr;
    struct sockaddr_storage src_sockaddr;

    if (resolve_probe_addresses(net_state, param, &dest_sockaddr,
                &src_sockaddr)) {
        printf("%d invalid-argument\n", param->command_token);
        return;
    }

    probe = alloc_probe(net_state, param->command_token);
    if (probe == NULL) {
        printf("%d probes-exhausted\n", param->command_token);
        return;
    }

    probe->platform.ip_version = param->ip_version;

    queue_thread_request(
        net_state, probe, param, &dest_sockaddr, &src_sockaddr);
}

/*
    After we've receive the result from the ICMP service thread,
    report either the probe status, or any Windows error we
    encountered while attempting to send the probe.
*/
static
void complete_icmp_result(struct icmp_thread_request_t *request)
{
    struct net_state_t *net_state;
    struct probe_t *probe;

    /*
        We can de-const the net_state and probe, since we are back
        on the main thread.
    */
    net_state = (struct net_state_t *)request->net_state;
    probe = (struct probe_t *)request->probe;

    if (request->icmp_type != -1) {
        /*  Record probe result  */
        respond_to_probe(net_state, probe,
                         request->icmp_type, &request->remote_addr,
                         request->round_trip_us, 0, NULL);
    } else {
        report_win_error(probe->token, request->reply_status);
        free_probe(net_state, probe);
    }
}

/*
    Read the status of completed probes from the ICMP service
    if any has completed.
*/
void receive_replies(
    struct net_state_t *net_state)
{
    int read_count;
    struct icmp_thread_request_t *request;

    read_count = read(
        net_state->platform.thread_out_pipe_read,
        &request,
        sizeof(struct icmp_thread_request_t *));

    if (read_count == -1) {
        /*
            EINTR and EAGAIN can occur under normal conditions, and
            should be retried.  We will retry the next iteration
            of the main loop.
        */
        if (errno == EINTR || errno == EAGAIN) {
            return;
        }

        error(EXIT_FAILURE, errno, "thread result pipe read error");
    }

    assert(read_count == sizeof(struct icmp_thread_request_t *));
    complete_icmp_result(request);

    if (request->reply4) {
        free(request->reply4);
        request->reply4 = NULL;
    }
    free(request);
}

/*
    On Windows, an implementation of check_probe_timeout is unnecessary because
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
