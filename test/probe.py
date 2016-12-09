#!/usr/bin/env python
#
#   mtr  --  a network diagnostic tool
#   Copyright (C) 2016  Matt Kimball
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

'''Test sending probes and receiving respones.'''

import re
import socket
import sys
import time
import unittest

import mtrpacket


IPV6_TEST_HOST = 'google-public-dns-a.google.com'


class TestProbeIPv4(mtrpacket.MtrPacketTest):
    '''Test sending probes using IP version 4'''

    def test_probe(self):
        'Test sending regular ICMP probes to known addresses'

        reply_regex = r'^14 reply ip-4 8.8.8.8 round-trip-time [0-9]+$'

        #  Probe Google's well-known DNS server and expect a reply
        self.write_command('14 send-probe ip-4 8.8.8.8')
        reply = self.read_reply()
        match = re.match(reply_regex, reply)
        self.assertIsNotNone(match)

    def test_timeout(self):
        'Test timeouts when sending to a non-existant address'

        no_reply_regex = r'^15 no-reply$'

        #
        #  Probe a non-existant address, and expect no reply
        #
        #  I'm not sure what the best way to find an address that doesn't
        #  exist, but is still route-able.  If we use a reserved IP
        #  address range, Windows will tell us it is non-routeable,
        #  rather than timing out when transmitting to that address.
        #
        #  We're just using a currently unused address in Google's
        #  range instead.  This is probably not the best solution.
        #

        # pylint: disable=locally-disabled, unused-variable
        for i in range(16):
            self.write_command('15 send-probe ip-4 8.8.254.254 timeout 1')
            reply = self.read_reply()
            match = re.match(no_reply_regex, reply)
            self.assertIsNotNone(match)

    def test_exhaust_probes(self):
        'Test exhausting all available probes'

        exhausted_regex = r'^[0-9]+ probes-exhausted$'

        match = None
        probe_count = 4 * 1024
        token = 1024

        # pylint: disable=locally-disabled, unused-variable
        for i in range(probe_count):
            command = str(token) + ' send-probe ip-4 8.8.254.254 timeout 60'
            token += 1
            self.write_command(command)

            reply = None
            try:
                reply = self.read_reply(0)
            except mtrpacket.ReadReplyTimeout:
                pass

            if reply:
                match = re.match(exhausted_regex, reply)
                if match:
                    break

        self.assertIsNotNone(match)

    def test_timeout_values(self):
        '''Test that timeout values wait the right amount of time

        Give each probe a half-second grace period to probe a timeout
        reply after the expected timeout time.'''

        begin = time.time()
        self.write_command('19 send-probe ip-4 8.8.254.254 timeout 0')
        self.read_reply()
        elapsed = time.time() - begin
        self.assertLess(elapsed, 0.5)

        begin = time.time()
        self.write_command('20 send-probe ip-4 8.8.254.254 timeout 1')
        self.read_reply()
        elapsed = time.time() - begin
        self.assertGreaterEqual(elapsed, 1.0)
        self.assertLess(elapsed, 1.5)

        begin = time.time()
        self.write_command('21 send-probe ip-4 8.8.254.254 timeout 3')
        self.read_reply()
        elapsed = time.time() - begin
        self.assertGreaterEqual(elapsed, 3.0)
        self.assertLess(elapsed, 3.5)

    def test_ttl_expired(self):
        'Test sending a probe which will have its time-to-live expire'

        ttl_expired_regex = \
            r'^16 ttl-expired ip-4 [0-9\.]+ round-trip-time [0-9]+$'

        #  Probe Goolge's DNS server, but give the probe only one hop
        #  to live.
        self.write_command('16 send-probe ip-4 8.8.8.8 ttl 1')
        reply = self.read_reply()
        match = re.match(ttl_expired_regex, reply)
        self.assertIsNotNone(match)

    def test_parallel_probes(self):
        '''Test sending multiple probes in parallel

        We will expect the probes to complete out-of-order by sending
        a probe to a distant host immeidately followed by a probe to
        the local host.'''

        reply_regex = \
            r'^[0-9]+ reply ip-4 [0-9\.]+ round-trip-time ([0-9]+)$'

        success_count = 0
        loop_count = 32

        # pylint: disable=locally-disabled, unused-variable
        for i in range(loop_count):
            #  Probe the distant host before the local host.
            self.write_command('17 send-probe ip-4 8.8.8.8 timeout 1')
            self.write_command('18 send-probe ip-4 127.0.0.1 timeout 1')

            reply = self.read_reply()
            match = re.match(reply_regex, reply)
            if not match:
                continue
            first_time = int(match.group(1))

            reply = self.read_reply()
            match = re.match(reply_regex, reply)
            if not match:
                continue
            second_time = int(match.group(1))

            #  Ensure we got a reply from the host with the lowest latency
            #  first.
            self.assertLess(first_time, second_time)

            success_count += 1

        #  We need 95% success to pass.  This allows a few probes to be
        #  occasionally dropped by the network without failing the test.
        required_success = int(loop_count * 0.95)
        self.assertGreaterEqual(success_count, required_success)


def resolve_ipv6_address(hostname):  # type: (str) -> str
    'Resolve a hostname to an IP version 6 address'

    for addrinfo in socket.getaddrinfo(hostname, 0):
        # pylint: disable=locally-disabled, unused-variable
        (family, socktype, proto, name, sockaddr) = addrinfo

        if family == socket.AF_INET6:
            sockaddr6 = sockaddr  # type: tuple

            (address, port, flow, scope) = sockaddr6
            return address

    raise LookupError(hostname)


def check_for_local_ipv6():
    '''Check for IPv6 support on the test host, to see if we should skip
    the IPv6 tests'''

    addrinfo = socket.getaddrinfo(IPV6_TEST_HOST, 1, socket.AF_INET6)
    if len(addrinfo):
        addr = addrinfo[0][4]

    #  Create a UDP socket and check to see it can be connected to
    #  IPV6_TEST_HOST.  (Connecting UDP requires no packets sent, just
    #  a route present.)
    sock = socket.socket(
        socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    connect_success = False
    try:
        sock.connect(addr)
        connect_success = True
    except socket.error:
        pass

    sock.close()

    if not connect_success:
        sys.stderr.write(
            'This host has no IPv6.  Skipping IPv6 tests.\n')

    return connect_success


class TestProbeIPv6(mtrpacket.MtrPacketTest):
    '''Test sending probes using IP version 6'''

    have_ipv6 = check_for_local_ipv6()

    def __init__(self, *args):
        google_addr = resolve_ipv6_address(IPV6_TEST_HOST)

        self.google_addr = google_addr  # type: str

        super(TestProbeIPv6, self).__init__(*args)

    @unittest.skipIf(not have_ipv6, 'No IPv6')
    def test_probe(self):
        "Test a probe to Google's public DNS server"

        reply_regex = r'^51 reply ip-6 [0-9a-f:]+ round-trip-time [0-9]+$'
        loopback_reply_regex = r'^52 reply ip-6 ::1 round-trip-time [0-9]+$'

        #  Probe Google's well-known DNS server and expect a reply
        self.write_command('51 send-probe ip-6 ' + self.google_addr)
        reply = self.read_reply()
        match = re.match(reply_regex, reply)
        self.assertIsNotNone(match, reply)

        #  Probe the loopback, and check the address we get a reply from is
        #  also the loopback.  While implementing IPv6, I had a bug where
        #  the low bits of the received address got zeroed.  This checks for
        #  that bug.
        self.write_command('52 send-probe ip-6 ::1')
        reply = self.read_reply()
        match = re.match(loopback_reply_regex, reply)
        self.assertIsNotNone(match, reply)

    @unittest.skipIf(not have_ipv6, 'No IPv6')
    def test_ttl_expired(self):
        'Test sending a probe which will have its time-to-live expire'

        ttl_expired_regex = \
            r'^53 ttl-expired ip-6 [0-9a-f:]+ round-trip-time [0-9]+$'

        #  Probe Goolge's DNS server, but give the probe only one hop
        #  to live.
        cmd = '53 send-probe ip-6 ' + self.google_addr + ' ttl 1'
        self.write_command(cmd)
        reply = self.read_reply()
        match = re.match(ttl_expired_regex, reply)
        self.assertIsNotNone(match, reply)


if __name__ == '__main__':
    mtrpacket.check_running_as_root()
    unittest.main()
