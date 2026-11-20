#!/usr/bin/env python3

'''Exercise filename parsing through mtr with a packet-helper fixture.'''

import os
import subprocess
import sys
import tempfile
import unittest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MTR = os.path.join(PROJECT_ROOT, 'mtr')


class TestFileHosts(unittest.TestCase):
    def check_hosts(self, contents, expected):
        for use_stdin in (False, True):
            with self.subTest(stdin=use_stdin), tempfile.TemporaryDirectory() as d:
                helper = os.path.join(d, 'packet-helper')
                log = os.path.join(d, 'targets')
                hosts = os.path.join(d, 'hosts')
                with open(hosts, 'w') as f:
                    f.write(contents)
                with open(helper, 'w') as f:
                    f.write('#!' + sys.executable + '\n' + '''import os
import sys
for line in sys.stdin:
    args = line.split()
    if args[1] == 'check-support':
        print(args[0] + ' feature-support support ok', flush=True)
    elif args[1] == 'send-probe':
        address = args[args.index('ip-4') + 1]
        with open(os.environ['MTR_TEST_TARGETS'], 'a') as output:
            output.write(address + '\\n')
        print(args[0] + ' reply ip-4 ' + address +
              ' round-trip-time 1000', flush=True)
''')
                os.chmod(helper, 0o700)
                env = os.environ.copy()
                env.pop('MTR_OPTIONS', None)
                env['MTR_PACKET'] = helper
                env['MTR_TEST_TARGETS'] = log
                reply = subprocess.run(
                    [MTR, '-4', '--report', '--no-dns', '-c', '1', '-m', '1',
                     '-G', '0.01', '--filename', '-' if use_stdin else hosts],
                    input=contents if use_stdin else None,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True, timeout=10, env=env,
                )
                self.assertEqual(reply.returncode, 0, reply.stderr)
                self.assertEqual(reply.stderr, '')
                with open(log) as f:
                    self.assertEqual(f.read().splitlines(), expected)

    def test_comments(self):
        self.check_hosts(
            '# header\n  # indented\n\n 127.0.0.1 # primary\r\n'
            '127.0.0.2#secondary\n\t127.0.0.3\t # third',
            ['127.0.0.1', '127.0.0.2', '127.0.0.3'],
        )

    def test_long_comments(self):
        self.check_hosts(
            '# ' + 'not-a-host ' * 200 + '\n127.0.0.1 # ' +
            'not-a-host ' * 200 + '\n127.0.0.2\n',
            ['127.0.0.1', '127.0.0.2'],
        )

    def test_uncommented_hosts(self):
        self.check_hosts('127.0.0.1\n127.0.0.2',
                         ['127.0.0.1', '127.0.0.2'])


if __name__ == '__main__':
    unittest.main()
