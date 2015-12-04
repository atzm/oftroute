Introduction
============
oftroute is an OpenFlow network tracing tool like traceroute(8) but works on
Layer-2, implemented as `Ryu <http://osrg.github.io/ryu/>`_ application.
It enables you to dynamically investigate forwarding route without changing
any your production flow entries.

Currently oftroute provides three commands below:

- oft-controller
- oft-ofctl
- oft-traceroute

oft-controller works as OpenFlow controller and RESTful API server.  You can
use command-line arguments built in ryu-manager, because it is implemented as
a Ryu application.

oft-ofctl works as a client for RESTful APIs provided by oft-controller.
As its name suggests, it partially works like ovs-ofctl(8) in
`Open vSwitch <http://openvswitch.org/>`_.
In fact, it provides functions for listing, adding, and deleting flow entries
on OpenFlow Switches that is connected to oft-controller.

oft-traceroute works as a client for RESTful APIs provided by oft-controller
too, but it works only for traceroute.  It requests traceroute process begin to
oft-controller, receives results, and displays them.

How it works
============
oftroute reserves just one value of an OXM field for traceroute.  It is used to
pick out the probe frame.  If OXM field is IEEE 802.1Q PCP and its value is 7,
oft-controller will install a flow entry for traceroute into OpenFlow Switches,
e.g.::

  table=0,priority=0xffff,metadata=0,dl_vlan_pcp=7
    actions=output:OFPP_CONTROLLER

When oft-traceroute requests traceroute process begin, oft-controller injects
an IEEE 802.1Q tag that contains PCP=7 into the probe frame received from
oft-traceroute, and sends a PACKET_OUT message with actions like::

  set_field:1->metadata,output:OFPP_TABLE

Metadata field is used to distinguish whether the probe frame came from outer
world or the controller.  It can be substituted by any OXM field that does not
affect to the probe frame.  If your environment does not use tunnel_id field to
know or configure virtual network identifier, tunnel_id field can be used
instead for instance.

Usage
=====

oft-controller
--------------
oft-controller is a simple wrapper of ryu-manager.  It works fine without any
command-line arguments::

  $ oft-controller

If you want to know about many command-line arguments built in ryu-manager,
you can see Ryu's documentation.

By default, oft-controller uses IEEE 802.1Q PCP=7 to pick out the probe frame,
and metadata field to distinguish whether probe frame came from outer world or
not.  But of course they are configurable.  If you want to use PCP=3 and
tunnel_id instead of metadata, you can configure as below::

  $ cat ryu.cfg
  [oftroute]
  metafield = tunnel_id
  ruleclass = RuleVlanPcp3

  $ oft-controller --config-file ryu.cfg

Full configurable items are:

- cookie

  - cookie is used to distinguish whether the PACKET_IN was occurred by oftroute
    or not.  It is useful when oftroute runs with other Ryu applications that
    let OpenFlow Switches send PACKET_IN.  Default: 0xfffffffffffffffe

- metafield

  - metafield is used to distinguish whether the probe frame came from outer
    world or the controller, as described above.  Default: metadata

- metavalue

  - metavalue is the value that is set to the field specified by metafield.
    It is used in when oft-controller sends PACKET_OUT message.
    Default: 0xfffffffffffffffe

- ruleclass

  - ruleclass is the class name to handle probe frame.  Currently it can be
    selected from RuleVlanPcp0 to RuleVlanPcp7.  Default: RuleVlanPcp7

oft-ofctl
---------
oft-ofctl controls OpenFlow Switches that is connected to oft-controller.
It has five subcommands listed below:

- list

  - list all OpenFlow Switches that is connected to oft-controller.

- show DPID

  - show details of an OpenFlow Switch.

- add-flow DPID FLOWENTRY

  - add a flow entry to an OpenFlow Switch.

- del-flows DPID FLOWENTRY

  - delete flow entries from an OpenFlow Switch.

- dump-flows DPID

  - show flow entries on an OpenFlow Switch.

DPID is represented in 16-digits hexadecimal number.

All flow entries are input or output by representation in
`ofpstr <https://pypi.python.org/pypi/ofpstr/>`_, for example::

  in_port=3,eth_type=0x806,@apply,set_eth_dst=00:00:00:00:00:02,output=2

This flow entry overwrites Ethernet destination address by 00:00:00:00:00:02
and outputs to port 2 when the frame is ARP and came from port 3.

oft-traceroute
--------------
oft-traceroute is a frontend for tracing OpenFlow network.  It sends probe
frame to oft-controller and requests traceroute process begin.

It requires three command-line arguments at least: probe frame type, DPID to
start traceroute, and input port number assuming that probe frame came from.
For example, if you want to send ARP request as it is input from port 1 on
DPID 1::

  $ oft-traceroute arp 0000000000000001 00000001

Some fields such as the Target Protocol Address can be specified by
command-line options.  For more details, you can see help message::

  $ oft-traceroute arp -h

Currently following probe frame types are available:

- arp
- udp4
- udp6
- tcp4
- tcp6
- raw

Type raw is a bit special.  It enables you to be free to specify probe frame.
Type raw requires more one command-line argument, to specify probe frame data
itself.  It is represented in hexadecimal numbers.  For example, if you want to
send following probe frame
(represented in `scapy <http://www.secdev.org/projects/scapy/>`_)::

  Ether(dst='ff:ff:ff:ff:ff:ff', src='5a:c5:4e:01:72:4e')
    Dot1Q(prio=7, vlan=100)
      IP(src='192.168.10.1', dst='255.255.255.255')
        UDP(sport=49152, dport=1324)

Then command-line arguments are::

  $ oft-traceroute raw 0000000000000001 00000001 \
  >   ffffffffffff5ac54e01724e8100e06408004500001c000100004011b027c0a80a01ffffffffc000052c00087008

Note that oft-controller will return error when specified frame is broken or
conflicted with rules for traceroute mechanism itself.

History
=======
0.0.1
  - First release

License
=======
oftroute is available under the Apache License Version 2.0.
