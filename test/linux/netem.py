'''
MtrNetEm - a small network emulation library

Description
-----------
This small, self-contained Python library serves as a high-level API for the
creation and management of virtual network topologies in a Linux environment.
By leveraging Linux's networking capabilities, it allows for the dynamic
establishment of virutal network environments, links, and complex route and rule
configurations. It only relies on iproute2, libc, and Python 3.10. The core
architecture revolves around the `Network` base class, from which custom network
topologies can be designed. A typical use-case involves inheriting from this base
class and defining `Host` and `Link` objects as class attributes within the
constructor. This design is essential because the assignment of these objects to
class attributes during the constructor's execution is what adds them to the
underlying network topology.

Key Features
------------
When defining a custom network topology, `Host` and `Link` objects must be
explicitly assigned to attributes within the constructor. This allows the base
class to properly register and manage these resources. Upon creation of the
network (when entering the `with` block or calling `create` on a network instance),
the library dynamically generates names for the resources — such as the network namespaces
for hosts and the names for links — enabling unique identification and isolation.

For example, the `SimpleNetwork` class in the code snippet below demonstrates the
creation of a basic network with two hosts (`host0` and `host1`) linked by a
virtual ethernet pair (`link`). IP addresses are then assigned to the interfaces
on this link for each host. The resource names for `Host` and `Link` objects,
like the network namespace names for hosts and the names for links, are automatically
assigned when the network is instantiated.

Usage Example
-------------
```python
# Create a simple network with two hosts connected on a link
class SimpleNetwork(Network):
    def __init__(self):
        super().__init__() # must be called first
        self.host0 = Host()
        self.host1 = Host()
        self.link = Link(self.host0, self.host1)
        self.host0.add_address('192.168.10.0/31', self.link)
        self.host1.add_address('192.168.10.1/31', self.link)

# Setup the network topology
with SimpleNetwork() as net:
    # Enter host0's network namespace
    with net.host0.netns():
        # ping host 1
        subprocess.run(['ping', '192.168.10.1'])
```

Debugging
---------
If the MTR_NETEM_TRACE environmental variable is defined, a trace
of all configuration commands will be written to standard error.
'''

# Standard library imports
import os
import sys
import subprocess
import platform
import functools
from dataclasses import dataclass
from enum import Enum
from functools import partial
from io import IOBase
from typing import Any, Dict, List, Optional, Tuple, Union, cast

# Third-party imports
from ctypes import CDLL, get_errno

##########################
## Network Topology API ##
##########################

# Enum to represent reverse path filtering options
# See RFC 3704
class Rpfilter(Enum):
    '''Reverse-path filtering kernel options'''

    DISABLED = 0
    STRICT = 1
    LOOSE = 2

# Data class to hold interface configuration
@dataclass
class Intf():
    '''Interface configuration'''

    addresses: List[str] # List of IP addresses for this interface
    name: Optional[str] = None # The link name is determined at configuration time
    rpfilter: Rpfilter = Rpfilter.LOOSE # Reverse path filter setting

@dataclass
class Route():
    '''Route configuration'''

    prefix: str # Network prefix (CIDR notation)
    device: Optional[Intf] = None # Optional output interface
    table: Optional[int] = None # Optional routing table ID


# Represents a policy routing rule
@dataclass
class Rule():
    '''Policy-routing rule'''

    not_: bool = False # Negate the rule
    from_: Optional[str] = None # Optional source address
    to: Optional[str] = None # Optional destination address
    fwmark: Optional[int] = 0 # Optional firewall mark
    table: Optional[int] = None # Routing table ID

class LifecycleException(Exception):
    pass

class Lifecycle(Enum):
    CONFIG = 0
    RUNTIME = 1

class NetworkObject():
    '''Base class for all network properties'''

    _parent : 'Network'

    def __init__(self):
        self._parent = None

    def _register_parent(self, net : 'Network'):
        self._parent = net

def lifecycle_method(method, lifecycle : Lifecycle):
    '''Wraps network object method enforcing it is called at a particular point
    in the lifecycle. This is important because configuration is static and cannot be
    changed after the network object is created. Some runtime methods reference data
    only available at runtime.'''

    @functools.wraps(method)
    def _ensure_phase(self: NetworkObject, *method_args, **method_kwargs):

        # self._parent may be None during the configuration phase
        if self._parent is not None or lifecycle != Lifecycle.CONFIG:

            current_phase = self._parent._phase

            if current_phase != lifecycle:
                raise LifecycleException(
                    f'{method.__name__} called during an incorrect stage in'
                    f'the emulation lifecycle: {current_phase}, should be called'
                    f'during {lifecycle}'
                )

        return method(self, *method_args, **method_kwargs)

    return _ensure_phase

# Create aliases for config and runtime calls
config_method = partial(lifecycle_method, lifecycle=Lifecycle.CONFIG)
runtime_method = partial(lifecycle_method, lifecycle=Lifecycle.RUNTIME)

class Link(NetworkObject):
    '''A link object represents a virtual ethernet pair that links two hosts'''

    hosts: Tuple[Optional['Host'], Optional['Host']]

    def __init__(self):
        '''Initialize a Link object with empty hosts.'''
        super().__init__()
        self.hosts = (None, None)

    @config_method
    def connect(self, host1 : 'Host', host2 : 'Host'):
        '''
        Connect two Host objects via this Link.

        Parameters:
        host1: First host to connect
        host2: Second host to connect
        '''

        self.hosts = (host1, host2)

        for host in self.hosts:
            host._register_link(self)

# Define a Host class to represent virtual host
# This is a network namespace with programmatic configuration
class Host(NetworkObject):
    '''A host represent a virtual host and is a member of a Network.
    This is essentially a network namespace with additional configuration
    including routes, rules, and interfaces.'''

    netns_name: Optional[str]
    _intf: Dict[Link, Intf]
    _routes: List[Route]
    _rules: List[Rule]
    ip_forwarding: bool

    def __init__(self, ip_forwarding=False):
        '''Initialize a Host object with optional IP forwarding.'''
        super().__init__()
        self.netns_name = None
        self._intf = {}
        self._routes = []
        self._rules = []
        self.ip_forwarding = ip_forwarding

    def _register_link(self, link : Link):
        '''
        Internal method to register a Link with this Host.

        Parameters:
        link: The link to register
        '''
        self._intf[link] = Intf(addresses = [])

    @config_method
    def add_address(self, address : str, dev : Link):
        '''
        Add an IP address to a specific interface associated with a link.

        Parameters:
        address (str): The IP address to add.
        dev (Link): The Link object representing the interface.
        '''

        self._intf[dev].addresses.append(address)

    @config_method
    def config_rpfiler(self, rp: Rpfilter, dev : Link):
        '''
        Set the reverse-pass filter for an interface associated with a link.
        '''
        self._intf[dev].rpfilter = rp

    @runtime_method
    def netns(self) -> 'NetNamespace':
        '''
        Retrieve the network namespace associated with this Host.

        Returns:
        NetNamespace: The network namespace object.
        '''
        return NetNamespace(cast(str, self.netns_name))

    def intf(self, link : Link) -> Intf:
        '''
        Retrieve the interface associated with a specific Link.

        Parameters:
        link (Link): The Link object to query for.

        Returns:
        Intf: The interface associated with the Link.
        '''
        return self._intf[link]

    @config_method
    def add_route(self, prefix_or_route: Union[str, Route], **kwargs):
        '''
        Add a route to the Host's routing table.

        Parameters:
        prefix_or_route (Union[str, Route]): Either a prefix (in CIDR format) or a Route object.
        kwargs: Additional optional arguments if prefix_or_route is a string.
        '''
        if isinstance(prefix_or_route, str):

            if 'device' in kwargs:
                device = kwargs['device']
                device = self._intf[device] if isinstance(device, Link) else device
                kwargs['device'] = device

            self.add_route(Route(
                prefix=prefix_or_route,
                **kwargs
            ))
        else:
            assert len(kwargs) == 0 # noqa: S101
            self._routes.append(prefix_or_route)

    @config_method
    def add_rule(self, rule: Optional[Rule] = None, **kwargs):
        '''
        Add a policy-based routing rule to this Host.

        Parameters:
        rule (Optional[Rule]): A Rule object, if None, a Rule will be created from kwargs.
        kwargs: Additional optional arguments to create a Rule object.
        '''
        if not rule:
            rule = Rule(**kwargs)

        self._rules.append(rule)

class Network():
    '''
    Network class that serves as a base class for virtual network
    topologies.
    '''

    name: str
    _hosts: Dict[str, Host]
    _links: Dict[str, Link]
    _phase: Lifecycle

    def __init__(self, name: Optional[str] = None):
        '''
        Initializes a Network object.

        Args:
        name (Optional[str], optional): The name of the network.
        Defaults to the class name if not provided.
        '''
        self.name = self.__class__.__name__ if name is None else name
        self._hosts = {}
        self._links = {}
        self._phase = Lifecycle.CONFIG

    def register_host(self, name : str, host : Host):
        self._hosts[name] = host

    def register_link(self, name : str, link : Link):
        self._links[name] = link

    def __setattr__(self, name : str, value : Any):
        if hasattr(value, '__class__') \
                and issubclass(value.__class__, NetworkObject):
            value._register_parent(self)

        if isinstance(value, Host):
            self.register_host(name, value)
        elif isinstance(value, Link):
            self.register_link(name, value)

        super().__setattr__(name, value)

    def __enter__(self):
        self.create()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.destroy()

    def create(self) -> None:
        '''
        Creates the virtual network topology. Creates network namespace and associated
        resources.
        '''

        assert self._phase == Lifecycle.CONFIG, \
                "Repeated calls to create() on a single network object" # noqa: S101


        for name, host in self._hosts.items():
            host.netns_name = f'{self.name}.{name}'

        for name, link in self._links.items():
            for i, host in enumerate(cast(Tuple[Host, Host], link.hosts)):
                host._intf[link].name = f'{name}{i}'

        try:
            create_network(self)
            self._phase = Lifecycle.RUNTIME
        except Exception as e:
            destroy_network(self)
            raise e

    def destroy(self) -> None:
        '''
        Destroys the virtual network topology by removing namespaces and
        associated resources
        '''
        assert self._phase == Lifecycle.RUNTIME, \
            "Network not setup" # noqa: S101


        destroy_network(self)
        self._phase = Lifecycle.CONFIG

def supported() -> Tuple[bool, Optional[str]]:
    return _supported()

__all__ = [ 'Link', 'Rpfilter', 'Intf', 'Route', 'Rule', 'Host', 'Network', 'supported' ]

########################
## NETWORK NAMESPACES ##
########################

LIB_C_SHARED_OBJ = 'libc.so.6'

# Define possible namespace clone flags
# Ensure the file descriptor refers to a specific namespace type
class CloneFlags(Enum):
    ANY = 0
    NEWCGROUP = 0x02000000
    NEWIPC = 0x08000000
    NEWNET = 0x40000000
    NEWNS = 0x00020000
    NEWPID = 0x20000000
    NEWTIME = 0x00000080
    NEWUSER = 0x10000000
    NEWUTS = 0x04000000


# Error handler for setns syscall
def setns_errhandler(ret : int, _func: Any, args: tuple):

    if ret == -1:
        e = get_errno()
        raise OSError(e, os.strerror(e))


# Initialize libc and setup error handler for setns
libc = CDLL(LIB_C_SHARED_OBJ)
libc.setns.errcheck = setns_errhandler


def setns(file : IOBase, nstype : CloneFlags):
    return libc.setns(file.fileno(), nstype.value)


# Custom exception for namespace errors
class NamespaceException(Exception):
    pass


# Class to manage network namespaces with the context manager
# Moves the process into the namespace specified by "name"
class NetNamespace(object):

    def __init__(self, name : str):
        self.name = name
        self.pid = os.getpid()
        self._target_ns = f'/var/run/netns/{name}'
        self._current_ns = f'/proc/{self.pid}/ns/net'
        self._current_ns_file = None

    def enter(self):
        try:
            self._current_ns_file = open(self._current_ns)

            with open(self._target_ns) as file:
                setns(file, CloneFlags.NEWNET)
        except FileNotFoundError:
            raise NamespaceException('Failed to open the namespace file. Does the namespace exit?')
        except PermissionError:
            raise NamespaceException('Failed to open the namespace file. Permission denied.')

    def exit(self):
        setns(self._current_ns_file, CloneFlags.NEWNET)
        self._current_ns_file.close()
        self._current_ns_file = None

    def __enter__(self):
        self.enter()

    def __exit__(self, exc_type, exc_value, traceback):
        self.exit()

    def __del__(self):
        if self._current_ns_file:
            self._current_ns_file.close()

####################
## IMPLEMENTATION ##
####################

# Enable tracing
MTR_NETEM_TRACE = len(os.getenv('MTR_NETEM_TRACE', '')) > 0


def find_ip_command() -> Optional[str]:
    '''
    Search for the location of the `ip` command in common directories.
    '''
    # List of possible locations where the `ip` command might be located
    possible_locations = [
        "/usr/bin/ip",
        "/sbin/ip",
        "/usr/sbin/ip",
        "/bin/ip"
    ]

    # Loop through the possible locations
    for location in possible_locations:
        # Check if the file exists and is executable
        if os.path.isfile(location) and os.access(location, os.X_OK):
            return location

    return None

def run_cmd(*args, **kargs):
    '''
    Execute a shell command.

    This function takes the same arguments as subprocess.run and executes the command.
    If MTR_NETEM_TRACE is enabled, the command will be traced (i.e., printed
    before execution).
    '''

    if MTR_NETEM_TRACE:
        cmd = ' '.join(args[0])
        print(cmd, file=sys.stderr)

    subprocess.run(*args, **kargs)

def rule_spec(rule : Rule) -> List[str]:
    '''
    Generate a list of arguments for iproute2 to create or delete a routing
    rule.
    This is the concatenation of the SELECTOR and ACTION for a rule.
    '''
    cmd: List[str] = []

    if rule.not_:
        cmd.append('not')

    if rule.from_:
        cmd.extend(['from', rule.from_])

    if rule.to:
        cmd.extend(['to', rule.to])

    if rule.fwmark:
        cmd.extend(['fwmark', str(rule.fwmark)])

    if rule.table:
        cmd.extend(['table', str(rule.table)])

    return cmd

def route_spec(route : Route) -> List[str]:
    '''
    Generate a list of arguments for iproute2 to create or delete a route.
    This is the concatenation of the SELECTOR and ACTION for a route.
    '''

    '''Obtain the concatenation of the SELECTOR and ACTION
    of an ip route command, useful for adding or deleting
    rules with iproute2'''

    cmd: List[str] = [ route.prefix ]

    if route.device:
        cmd.extend(['dev', cast(str, route.device.name)])

    if route.table:
        cmd.extend(['table', str(route.table)])

    return cmd

def set_kernel_opt(path : str, value : Union[str, int]):
    '''
    Set a kernel option by writing to a sysfs or procfs entry.
    '''

    try:
        with open(path, 'w') as file:
            file.write(str(value))
    except Exception as e:
        raise RuntimeError(f'Failed to configure kernel option: {str(e)}')

def set_interface_rpfiler(intf_name : str, rpfilter : Rpfilter):
    '''
    Configure the reverse path filter setting for a network interface.
    '''

    set_kernel_opt(
        f'/proc/sys/net/ipv4/conf/{intf_name}/rp_filter', rpfilter.value
    )

def set_ip_forwarding(forward : bool):
    '''Enable or disable IP forwarding.'''

    set_kernel_opt('/proc/sys/net/ipv4/ip_forward', int(forward))

def create_network(net : Network):
    '''
    Create a virtual network.

    This involves several steps:
    1. Creating network namespaces for each host.
    2. Creating virtual ethernet pairs for each link.
    3. Configuring each network interface and moving it to the appropriate namespace.
    4. Setting up routes and rules for each host.

    '''

    cmd = partial(run_cmd, check=True)

    ip_cmd = cast(str, find_ip_command())

    # Add host namespaces
    host : Host
    for host in net._hosts.values():
        cmd([ ip_cmd, 'netns', 'add', host.netns_name ], check=True)

    link : Link
    for link in net._links.values():

        intfs = tuple(host._intf[link] \
                for host in cast(Tuple[Host, Host], link.hosts))

        # Add a virtual ethernet link
        cmd([
            ip_cmd, 'link', 'add', intfs[0].name,
            'type', 'veth', 'peer', 'name',
            intfs[1].name
        ])

        intf : Intf
        for host, intf in zip(cast(Tuple[Host, Host], link.hosts), intfs):
            intf_name = cast(str, intf.name)
            netns_name = cast(str, host.netns_name)

            # Move a end of the link pair into the host's network namespace
            cmd([ip_cmd, 'link', 'set', intf_name, 'netns', netns_name])

            with NetNamespace(netns_name):
                # Configure the reverse pass filter
                set_interface_rpfiler(intf_name, intf.rpfilter)

                # Add IP addresses to the link
                for addr in intf.addresses:
                    cmd([ip_cmd, 'addr', 'add', addr, 'dev', intf_name])

                # Activate the interface
                cmd([ip_cmd, 'link', 'set', intf.name, 'up'])

    for host in net._hosts.values():

        with NetNamespace(cast(str, host.netns_name)):
            # Configure the host's ip forwarding
            set_ip_forwarding(host.ip_forwarding)

            # Add the host's routes
            for route in host._routes:
                cmd([ip_cmd, 'route', 'add', *route_spec(route)])

            # Add the host's policy-database rules
            for rule in host._rules:
                cmd([ip_cmd, 'rule', 'add', *rule_spec(rule)])

def destroy_network(net : Network):
    '''
    Destroy a virtual network.

    This will remove all network namespaces and associated resources created during network setup.
    '''

    ip_cmd = cast(str, find_ip_command())

    host : Host
    for host in net._hosts.values():
        run_cmd([ip_cmd, 'netns', 'delete', host.netns_name])

# /usr/bin/ip
# /sbin/ip

def has_iproute() -> bool:
    '''Test if the host has iproute2 ensuring `ip -V` returns 0'''

    ip_cmd = find_ip_command()

    if ip_cmd is None:
        return False

    try:
        ip_result = subprocess.run([ip_cmd, '-V'], capture_output=True)
    except:
        return False

    return ip_result.returncode == 0

def _supported() -> Tuple[bool, Optional[str]]:
    '''Test if MtrNetEm is supported'''

    if platform.system() != 'Linux':
        return False, 'Tests are only supported on Linux'

    parts = platform.release().split('.')
    major, minor = int(parts[0]), int(parts[1])

    # Linux 3.8 added the 'setns' network namespace flag
    if (major < 3) or (major == 3 and minor < 8):
        return False, 'Tests are only supported on Linux kernel version >= 3.8'

    if os.getuid() != 0:
        return False, 'Network emulation test require root'

    if not has_iproute():
        return False, 'The ip utility must be installed (iproute2)'

    return True, None

