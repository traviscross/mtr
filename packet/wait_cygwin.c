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

#include "wait.h"

#include <error.h>
#include <sys/select.h>

#include "command.h"

/*
    Wait for either a request from the command stream or
    for the probe results to be passed from the ICMP service
    thread.
*/
void wait_for_activity(
    struct command_buffer_t *command_buffer,
    struct net_state_t *net_state)
{
    int nfds;
    fd_set read_set;
    int ready_count;

    FD_ZERO(&read_set);

    FD_SET(command_buffer->command_stream, &read_set);
    nfds = command_buffer->command_stream + 1;

    FD_SET(net_state->platform.thread_out_pipe_read, &read_set);
    if (net_state->platform.thread_out_pipe_read >= nfds) {
        nfds = net_state->platform.thread_out_pipe_read + 1;
    }

    while (true) {
        ready_count =
            select(nfds, &read_set, NULL, NULL, NULL);

        if (ready_count != -1) {
            return;
        }

        /*
            EINTR and EAGAIN simply mean that the select should
            be retried.
        */
        if (errno != EINTR && errno != EAGAIN) {
            error(EXIT_FAILURE, errno, "unexpected select error");
        }
    }
}
