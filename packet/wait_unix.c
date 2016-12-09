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

#include "wait.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>

/*
    Sleep until we receive a new probe response, a new command on the
    command stream, or a probe timeout.  On Unix systems, this means
    we use select to wait on file descriptors for the command stream
    and the raw recieve socket.
*/
void wait_for_activity(
    struct command_buffer_t *command_buffer,
    struct net_state_t *net_state)
{
    int nfds;
    fd_set read_set;
    struct timeval probe_timeout;
    struct timeval *select_timeout;
    int ready_count;
    int command_stream = command_buffer->command_stream;
    int ipv4_socket = net_state->platform.ipv4_recv_socket;
    int ipv6_socket = net_state->platform.ipv6_recv_socket;

    FD_ZERO(&read_set);
    FD_SET(command_stream, &read_set);
    nfds = command_stream + 1;

    FD_SET(ipv4_socket, &read_set);
    if (ipv4_socket >= nfds) {
        nfds = ipv4_socket + 1;
    }

    FD_SET(ipv6_socket, &read_set);
    if (ipv6_socket >= nfds) {
        nfds = ipv6_socket + 1;
    }

    while (true) {
        select_timeout = NULL;

        /*  Use the soonest probe timeout time as our maximum wait time  */
        if (get_next_probe_timeout(net_state, &probe_timeout)) {
            assert(probe_timeout.tv_sec >= 0);
            select_timeout = &probe_timeout;
        }

        ready_count = select(nfds, &read_set, NULL, NULL, select_timeout);

        /*
            If we didn't have an error, either one of our descriptors is
            readable, or we timed out.  So we can now return.
        */
        if (ready_count != -1) {
            break;
        }

        /*
            We will get EINTR if we received a signal during the select, so
            retry in that case.  We may get EAGAIN if "the kernel was
            (perhaps temporarily) unable to allocate the requested number of
            file descriptors."  I haven't seen this in practice, but selecting
            again seems like the right thing to do.
        */
        if (errno != EINTR && errno != EAGAIN) {
            /*  We don't expect other errors, so report them  */
            perror("unexpected select error");
            exit(1);
        }
    }
}
