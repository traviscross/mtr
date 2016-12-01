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

#include <io.h>
#include <stdio.h>
#include <windows.h>

/*
    Sleep until we receive a new probe response, a new command on the
    command stream, or a probe timeout.  On Windows, this means that
    we will sleep with an alertable wait, as all of these conditions
    use I/O completion routines as notifications of these events.
*/
void wait_for_activity(
    const struct command_buffer_t *command_buffer,
    const struct net_state_t *net_state)
{
    DWORD wait_result;

    /*  Sleep until an I/O completion routine runs  */
    wait_result = SleepEx(INFINITE, TRUE);

    if (wait_result == WAIT_FAILED) {
        fprintf(stderr, "SleepEx failure %d\n", GetLastError());
        exit(1);
    }
}
