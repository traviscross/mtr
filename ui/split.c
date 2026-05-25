/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997  Matt Kimball

    split.c -- raw output (for inclusion in KDE Network Utilities or others
                         GUI based tools)
    Copyright (C) 1998  Bertrand Leconte <B.Leconte@mail.dotcom.fr>

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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "mtr.h"
#include "display.h"
#include "dns.h"

#include "net.h"
#include "split.h"
#include "utils.h"


/* There is 256 hops max in the IP header (coded with a byte) */
#define MAX_LINE_COUNT 256
#define MAX_LINE_SIZE  1024

static char Lines[MAX_LINE_COUNT][MAX_LINE_SIZE];
static int LineCount;
static struct termios saved_termios;
static int have_saved_termios;


static void split_restore_terminal(
    void)
{
    if (have_saved_termios) {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
        have_saved_termios = 0;
    }
}


#define DEBUG 0


void split_redraw(
    struct mtr_ctl *ctl)
{
    int max;
    int at;
    ip_t *addr;
    char newLine[MAX_LINE_SIZE];
    int i;

#if DEBUG
    fprintf(stderr, "split_redraw()\n");
#endif

    /*
     * If there is less lines than last time, we delete them
     * TEST THIS PLEASE
     */
    max = net_max(ctl);
    for (i = LineCount; i > max; i--) {
        printf("-%d\n", i);
        LineCount--;
    }

    /*
     * For each line, we compute the new one and we compare it to the old one
     */
    for (at = 0; at < max; at++) {
        addr = net_addr(at);
        if (addrcmp(addr, &ctl->unspec_addr, ctl->af)) {
            char str[256], *name;
            if (!(name = dns_lookup(ctl, addr)))
                name = strlongip(ctl->af, addr);
            if (ctl->show_ips) {
                snprintf(str, sizeof(str), "%s %s", name,
                         strlongip(ctl->af, addr));
                name = str;
            }
            /* May be we should test name's length */
            snprintf(newLine, sizeof(newLine), "%s %d %d %d %.1f %.1f %.1f",
                     name, net_loss(at), net_returned(at), net_xmit(at),
                     net_best(at) / 1000.0, net_avg(at) / 1000.0,
                     net_worst(at) / 1000.0);
        } else {
            snprintf(newLine, sizeof(newLine), "???");
        }

        if (strcmp(newLine, Lines[at]) != 0) {
	    // something changed, so we print it.
            printf("%d %s\n", at + 1, newLine);
            fflush(stdout);
           // xstrncpy(Lines[at], newLine, MAX_LINE_SIZE);
            snprintf(Lines[at], MAX_LINE_SIZE, "%s", newLine);
            if (LineCount < (at + 1)) {
                LineCount = at + 1;
            }
        } else {
            /* The same, so do nothing */
#if DEBUG
            printf("SAME LINE\n");
#endif
        }
    }
}


void split_open(
    void)
{
    int i;
    struct termios raw_termios;
#if DEBUG
    printf("split_open()\n");
#endif
    LineCount = -1;
    for (i = 0; i < MAX_LINE_COUNT; i++) {
        xstrncpy(Lines[i], "", MAX_LINE_SIZE);
    }

    if (isatty(STDIN_FILENO) &&
        tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
        raw_termios = saved_termios;
        raw_termios.c_lflag &= ~ICANON;
        raw_termios.c_cc[VMIN] = 0;
        raw_termios.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw_termios) == 0) {
            have_saved_termios = 1;
            atexit(split_restore_terminal);
        }
    }
}


void split_close(
    void)
{
#if DEBUG
    printf("split_close()\n");
#endif
    split_restore_terminal();
}


int split_keyaction(
    void)
{
    fd_set readfds;
    struct timeval tv;
    char c;
    int rv;

    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    do {
        rv = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);
    } while (rv < 0 && errno == EINTR);

    if (rv > 0) {
        if (read(STDIN_FILENO, &c, 1) <= 0)
            return ActionQuit;
    } else {
        return 0;
    }

#if DEBUG
    printf("split_keyaction()\n");
#endif
    if (tolower(c) == 'q')
        return ActionQuit;
    if (c == 3)
        return ActionQuit;
    if (tolower(c) == 'r')
        return ActionReset;
    if (tolower(c) == 'p')
        return ActionPause;
    if (c == ' ')
        return ActionResume;
    if (tolower(c) == 'd')
        return ActionDisplay;
    if (tolower(c) == 'c')
        return ActionCompact;
    if (tolower(c) == 'e')
        return ActionMPLS;
    if (tolower(c) == 'n')
        return ActionDNS;
    if (c == '+')
        return ActionScrollDown;
    if (c == '-')
        return ActionScrollUp;

    return 0;
}
