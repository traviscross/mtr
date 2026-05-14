/*
    mtr  --  a network diagnostic tool
    Copyright (C) 2026  Darafei Praliaskouski

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

#ifndef PORTS_H
#define PORTS_H

#define MTR_PORT_MIN 1
#define MTR_PORT_MAX 65535
#define MTR_UNPRIVILEGED_PORT_MIN 1024
#define MTR_UDP_PORT_RANGE 65536

#define MTR_IS_VALID_PORT(port) \
    ((port) >= MTR_PORT_MIN && (port) <= MTR_PORT_MAX)

#define MTR_IS_PRIVILEGED_PORT(port) \
    ((port) >= MTR_PORT_MIN && (port) < MTR_UNPRIVILEGED_PORT_MIN)

#endif
