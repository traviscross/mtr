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

#include "config.h"

#include <errno.h>
#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif

#include "wait.h"

#define N_ENTRIES(array) \
    (sizeof((array)) / sizeof(*(array)))

#ifdef HAVE_LIBCAP
static
void drop_excess_capabilities() {
    cap_value_t cap_permitted[] = {
#ifdef SO_MARK
    /*
      By default, the root user has all capabilities, which poses a security risk.
      Since the socket has already been opened, we only need CAP_NET_ADMIN to set
      the fwmark. This capability must remain in the permitted set so that it can
      be added to the effective set when needed.
    */
        CAP_NET_ADMIN
#endif /* ifdef SOMARK */
    };

    cap_t current_cap = cap_get_proc();
    cap_t wanted_cap = cap_get_proc();

    if(!current_cap || !wanted_cap) {
        goto pcap_error;
    }

    // Clear all capabilities from the 'wanted_cap' set
    if(cap_clear(wanted_cap)) {
        goto pcap_error;
    }

    // Retain only the necessary capabilities defined in 'cap_permitted' in the permitted set.
    // This approach ensures the principle of least privilege.
    // If the user has dropped capabilities, the code assumes those features will not be needed.
    for(unsigned i = 0; i < N_ENTRIES(cap_permitted); i++) {
        cap_flag_value_t is_set;

        if(cap_get_flag(current_cap, cap_permitted[i], CAP_PERMITTED, &is_set)) {
            goto pcap_error;
        }

        if(cap_set_flag(wanted_cap, CAP_PERMITTED, 1, &cap_permitted[i], is_set)) {
            goto pcap_error;
        }
    }

    // Update the process's capabilities to match 'wanted_cap'
    if(cap_set_proc(wanted_cap)) {
        goto pcap_error;
    }

    if(cap_free(current_cap) || cap_free(wanted_cap)) {
        goto pcap_error;
    }

    return;

pcap_error:

    cap_free(current_cap);
    cap_free(wanted_cap);
    error(EXIT_FAILURE, errno, "Failed to drop capabilities");
}
#endif /* ifdef HAVE_LIBCAP */

/*  Drop SUID privileges.  To be used after acquiring raw sockets.  */
static
int drop_elevated_permissions(
    void)
{
    /*  Drop any suid permissions granted  */
    if (setgid(getgid()) || setuid(getuid())) {
        return -1;
    }

    if (geteuid() != getuid() || getegid() != getgid()) {
        return -1;
    }

    /*
       Drop all process capabilities.
     */
#ifdef HAVE_LIBCAP
    drop_excess_capabilities();
#endif

    return 0;
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
    if (drop_elevated_permissions()) {
        error(EXIT_FAILURE, errno, "Unable to drop elevated permissions");
    }
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
                if (errno == EPIPE) {
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
            if (net_state.outstanding_probe_count == 0) {
                break;
            }
        }
    }

    return 0;
}
