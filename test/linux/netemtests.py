'''
Tests requiring network emulation
'''

import sys
import unittest
import netem
from netem import Host, Link, Network, Rpfilter
from pathlib import Path
from typing import TypeVar, Type

# Allow imports from the parent directory
#
# This is not a "first-party" test since it is not
# cross-platform.

dir_path = Path(__file__).resolve().parent
sys.path.append(str(dir_path.parent))

import mtrpacket

NetworkDerivative = TypeVar('NetworkDerivative', bound=Network)

class MtrEmulatedPacketTest(mtrpacket.MtrPacketTest):
    '''Base class for network emulation packet tests.
    Ensures that the network is set up before executing any tests,
    and tears down the network after all tests have been executed.
    '''

    Net: NetworkDerivative
    net: Type[NetworkDerivative]

    @classmethod
    def setUpClass(cls):
        net = cls.Net()
        net.create()
        cls.net = net

        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        cls.net.destroy()
        super().tearDownClass()


class DualIntf(Network):
    '''
     DualIntf Topology: A network with two links
     useful for testing interface, route, or ip
     selection.

     HOST0                               HOST1
     ┌─────────┐ 172.30.1.0              ┌────────┐
     │ LINKA0  ├─────────────────────────┤ LINKA1 │
     │         │               172.30.1.1│        │
     │         │                         │        │
     │         │ 172.30.2.0              │        │
     │ LINKB0  ├─────────────────────────┤ LINKB1 │
     │         │               172.30.2.1│        │
     └─────────┘                         └────────┘
    '''

    def __init__(self):
        super().__init__()

        host0 = Host()
        host1 = Host()

        link_a = Link()
        link_a.connect(host0, host1)

        link_b = Link()
        link_b.connect(host0, host1)

        # Only respond to inbound traffic from the peer link
        host1.config_rpfiler(Rpfilter.STRICT, link_a)
        host1.config_rpfiler(Rpfilter.STRICT, link_b)

        host0.add_address('172.30.1.0/31', link_a)
        host1.add_address('172.30.1.1/31', link_a)

        host0.add_address('172.30.2.0/31', link_b)
        host1.add_address('172.30.2.1/31', link_b)

        host0.add_route('172.30.1.0/31', device=link_a, table=100)
        host0.add_rule(fwmark=100, table=100)

        self.host0 = host0
        self.host1 = host1

        self.link_a = link_a
        self.link_b = link_b

class DualIntfPacketTest(MtrEmulatedPacketTest):
    '''Test components that require a reproducible network topology'''

    Net = DualIntf

    def setUp(self):
        '''Enter the namespace for host0'''
        self.ns = DualIntfPacketTest.net.host0.netns()
        self.ns.enter()

        super().setUp()

    def tearDown(self):
        '''Exit the namespace for host0'''
        self.ns.exit()

        super().tearDown()

    def test_interface_binding(self):
        '''Test binding to a specific interface by sending a routable probe to an
        interface where the probe is not routable.'''

        # use link 'a'
        intf_a_h0 = self.net.host0.intf(self.net.link_a)

        # Expect a reply because 172.30.1.1 is on link 'a'
        self.write_command(f'14 send-probe ip-4 172.30.1.1 local-device {intf_a_h0.name} timeout 1')
        reply = self.parse_reply()
        self.assertEqual(reply.token, 14)
        self.assertEqual(reply.command_name, 'reply')
        self.assertEqual(reply.argument['ip-4'], '172.30.1.1')

        # Expect no reply because 172.30.2.1 is on link 'b'
        self.write_command(f'15 send-probe ip-4 172.30.2.1 local-device {intf_a_h0.name} timeout 1')
        reply = self.parse_reply()
        self.assertEqual(reply.token, 15)
        self.assertEqual(reply.command_name, 'no-reply')

    def test_packet_marking(self):
        '''Test if mtr-packet marks outbound packets.'''

        # Probes with mark '100' query a table that can only reach link 'a'

        # A probe destined for 172.30.1.1 on link 'a' should succeed
        self.write_command('16 send-probe ip-4 172.30.1.1 mark 100')
        reply = self.parse_reply()
        self.assertEqual(reply.token, 16)
        self.assertEqual(reply.command_name, 'reply')

        # A probe destined for 172.30.2.1 on link 'a' should not succeed
        self.write_command('17 send-probe ip-4 172.30.2.1 mark 100')
        reply = self.parse_reply()
        self.assertEqual(reply.token, 17)
        self.assertEqual(reply.command_name, 'no-reply')

    def test_source_address_selection(self):
        '''Test manual specification of a source address.'''

        # Send a probe to 172.30.1.1 via 172.30.1.0; host2 should respond
        self.write_command('18 send-probe ip-4 172.30.1.1 local-address 172.30.1.0')
        reply = self.parse_reply()
        self.assertEqual(reply.token, 18)
        self.assertEqual(reply.command_name, 'reply')

        # Send a probe to 172.30.2.1 via 172.30.1.0; host1 will not respond
        # because rp_filter is enabled and the probe is sent over link 'a'
        self.write_command('19 send-probe ip-4 172.30.2.1 local-address 172.30.1.0')
        reply = self.parse_reply()
        self.assertEqual(reply.token, 19)
        self.assertEqual(reply.command_name, 'no-reply')

if __name__ == '__main__':
    supported, err = netem.supported()

    if not supported:
        print(err, file=sys.stderr)
        sys.exit(1)

    unittest.main()
