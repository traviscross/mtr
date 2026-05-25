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

#ifndef CMDPARSE_H
#define CMDPARSE_H

enum {
    MAX_COMMAND_ARGUMENTS = 16,
    MAX_COMMAND_TOKENS = MAX_COMMAND_ARGUMENTS * 2 + 2
};

#define COMMAND_NAME_SEND_PROBE "send-probe"

#define COMMAND_ARG_BIT_PATTERN "bit-pattern"
#define COMMAND_ARG_IP4 "ip-4"
#define COMMAND_ARG_IP6 "ip-6"
#define COMMAND_ARG_LOCAL_DEVICE "local-device"
#define COMMAND_ARG_LOCAL_IP4 "local-ip-4"
#define COMMAND_ARG_LOCAL_IP6 "local-ip-6"
#define COMMAND_ARG_LOCAL_PORT "local-port"
#define COMMAND_ARG_MARK "mark"
#define COMMAND_ARG_PORT "port"
#define COMMAND_ARG_PROTOCOL "protocol"
#define COMMAND_ARG_SIZE "size"
#define COMMAND_ARG_TIMEOUT "timeout"
#define COMMAND_ARG_TOS "tos"
#define COMMAND_ARG_TTL "ttl"

#define COMMAND_PROTOCOL_ICMP "icmp"
#define COMMAND_PROTOCOL_SCTP "sctp"
#define COMMAND_PROTOCOL_TCP "tcp"
#define COMMAND_PROTOCOL_UDP "udp"

/*  Parsed commands, or command replies, ready for semantic interpretation  */
struct command_t {
    /*  A unique value for matching command requests with replies  */
    int token;

    /*  Text indicating the command type, or reply type  */
    char *command_name;

    /*  The number of key, value argument pairs used  */
    int argument_count;

    /*  Names for each argument  */
    char *argument_name[MAX_COMMAND_ARGUMENTS];

    /*  Values for each argument, parallel to the argument_name array  */
    char *argument_value[MAX_COMMAND_ARGUMENTS];
};

int parse_command(
    struct command_t *command,
    char *command_string);

#endif
