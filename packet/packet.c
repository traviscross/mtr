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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "wait.h"

/*  Drop SUID privileges.  To be used after accquiring raw sockets.  */
static
void drop_suid_permissions(void)
{
    if (setgid(getgid()) || setuid(getuid())) {
        perror("Unable to drop suid permissions");
    }

    if (geteuid() != getuid() || getegid() != getgid()) {
        perror("Unable to drop suid permissions");
    }
}

int main(
    int argc,
    char **argv)
{
    bool command_pipe_open;
    struct command_buffer_t command_buffer;
    struct net_state_t net_state;

    /*
        To minimize security risk, the only thing done prior to 
        dropping SUID should be opening the network state for
        raw sockets.
    */
    init_net_state_privileged(&net_state);
    drop_suid_permissions();
    init_net_state(&net_state);

    init_command_buffer(&command_buffer, fileno(stdin));

    command_pipe_open = true;

    /*
        Dispatch commands and respond to probe replies until the
        command stream is closed.
    */
    while (true) {
        /*  Ensure any responses are written before waiting  */
        fflush(stdout);
        wait_for_activity(&command_buffer, &net_state);

        /*
            Receive replies first so that the timestamps are as
            close to the response arrival time as possible.
        */
        receive_replies(&net_state);

        if (command_pipe_open) {
            if (read_commands(&command_buffer)) {
                if (errno == EPIPE)
                {
                    command_pipe_open = false;
                }
            }
        }

        check_probe_timeouts(&net_state);

        /*
            Dispatch commands late so that the window between probe
            departure and arriving replies is as small as possible.
        */
        dispatch_buffer_commands(&command_buffer, &net_state);

        /*
            If the command pipe has been closed, exit after all
            in-flight probes have reported their status.
        */
        if (!command_pipe_open) {
            if (count_in_flight_probes(&net_state) == 0) {
                break;
            }
        }
    }

    return 0;
}
