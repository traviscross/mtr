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


'''Test mtr-packet's functionality

Test the ability to send probes and receive replies using mtr-packet.
'''

# pylint: disable=locally-disabled, import-error
import fcntl
import os
import re
import select
import subprocess
import sys
import time
import unittest


class ReadReplyTimeout(Exception):
    'Exception raised by TestProbe.read_reply upon timeout'

    pass


class TestProbe(unittest.TestCase):
    'Test cases for sending and receiving probes'

    def __init__(self, *args):
        self.reply_buffer = None  # type: str
        self.packet_process = None  # type: subprocess.Popen
        self.stdout_fd = None  # type: int

        super(TestProbe, self).__init__(*args)

    def setUp(self):
        'Set up a test case by spawning a mtr-packet process'

        packet_path = os.environ.get('MTR_PACKET', './mtr-packet')

        self.reply_buffer = ''
        self.packet_process = subprocess.Popen(
            [packet_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)

        #  Put the mtr-packet process's stdout in non-blocking mode
        #  so that we can read from it without a timeout when
        #  no reply is available.
        self.stdout_fd = self.packet_process.stdout.fileno()
        flags = fcntl.fcntl(self.stdout_fd, fcntl.F_GETFL)

        # pylint: disable=locally-disabled, no-member
        fcntl.fcntl(self.stdout_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def tearDown(self):
        'After a test, kill the running mtr-packet instance'

        try:
            self.packet_process.kill()
        except OSError:
            return

    def write_command(self, cmd):  # type: (str) -> None
        'Send a command string to the mtr-packet instance'

        self.packet_process.stdin.write(cmd + '\n')
        self.packet_process.stdin.flush()

    def read_reply(self, timeout=10.0):  # type: (float) -> str
        '''Read the next reply from mtr-packet.

        Attempt to read the next command reply from mtr-packet.  If no reply
        is available withing the timeout time, raise ReadReplyTimeout
        instead.'''

        start_time = time.time()

        #  Read from mtr-packet until either the timeout time has elapsed
        #  or we read a newline character, which indicates a finished
        #  reply.
        while True:
            now = time.time()
            elapsed = now - start_time

            select_time = timeout - elapsed
            if select_time < 0:
                select_time = 0

            select.select([self.stdout_fd], [], [], select_time)

            try:
                self.reply_buffer += os.read(self.stdout_fd, 1024)
            except OSError:
                pass

            #  If we have read a newline character, we can stop waiting
            #  for more input.
            newline_ix = self.reply_buffer.find('\n')
            if newline_ix != -1:
                break

            if elapsed >= timeout:
                raise ReadReplyTimeout()

        reply = self.reply_buffer[:newline_ix]
        self.reply_buffer = self.reply_buffer[newline_ix + 1:]
        return reply

    def test_unknown_command(self):
        'Test sending a command unknown to mtr-packet'

        self.write_command('13 argle-bargle')
        self.assertEqual(self.read_reply(), '13 unknown-command')

    def test_malformed_command(self):
        'Test sending a malformed command request to mtr-packet'

        self.write_command('malformed')
        self.assertEqual(self.read_reply(), '0 command-parse-error')

    def test_exit_on_stdin_closed(self):
        '''Test that the packet process terminates after stdin is closed

        Test that, when outstanding requests are complete, the process
        terminates following stdin being closed.'''

        self.write_command('15 send-probe ip-4 8.8.254.254 timeout 1')
        self.packet_process.stdin.close()
        time.sleep(2)
        self.read_reply()
        exit_code = self.packet_process.poll()
        self.assertIsNotNone(exit_code)

    def test_probe(self):
        'Test sending regular ICMP probes to known addresses'

        reply_regex = r'^14 reply ip-4 8.8.8.8 round-trip-time [0-9]+$'

        #  Probe Google's well-known DNS server and expect a reply
        self.write_command('14 send-probe ip-4 8.8.8.8')
        reply = self.read_reply()
        match = re.match(reply_regex, reply)
        self.assertIsNotNone(match)

    def test_invalid_argument(self):
        'Test sending invalid arguments with probe requests'

        invalid_argument_regex = r'^[0-9]+ invalid-argument$'

        bad_commands = [
            '22 send-probe',
            '23 send-probe ip-4 str-value',
            '24 send-probe ip-4 8.8.8.8 timeout str-value',
            '25 send-probe ip-4 8.8.8.8 ttl str-value',
        ]

        for cmd in bad_commands:
            self.write_command(cmd)
            reply = self.read_reply()
            match = re.match(invalid_argument_regex, reply)
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
        id = 1024
        for i in range(probe_count):
            command = str(id) + ' send-probe ip-4 8.8.254.254 timeout 60'
            id += 1
            self.write_command(command)

            reply = None
            try:
                reply = self.read_reply(0)
            except ReadReplyTimeout:
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

    def test_versioning(self):
        'Test version checks and feature support checks'

        feature_tests = [
            ('30 check-support feature version',
             r'^30 feature-support support [0-9]+\.[0-9a-z\-\.]+$'),
            ('31 check-support feature ip-4',
             r'^31 feature-support support ok$'),
            ('32 check-support feature send-probe',
             r'^32 feature-support support ok$'),
            ('33 check-support feature bogus-feature',
             r'^33 feature-support support no$')
        ]

        for (request, regex) in feature_tests:
            self.write_command(request)
            reply = self.read_reply()
            match = re.match(regex, reply)
            self.assertIsNotNone(match)

    def test_command_overflow(self):
        'Test overflowing the incoming command buffer'

        big_buffer = 'x' * (64 * 1024)
        self.write_command(big_buffer)

        reply = self.read_reply()
        self.assertEqual(reply, '0 command-buffer-overflow')


if __name__ == '__main__':
    # pylint: disable=locally-disabled, no-member
    if sys.platform != 'cygwin' and os.getuid() > 0:
        sys.stderr.write(
            "Warning: Many tests require running as root\n")

    unittest.main()
