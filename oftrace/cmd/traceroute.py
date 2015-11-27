# -*- coding: utf-8 -*-

import json
import socket
import argparse
import binascii

import websocket

import ryu.lib.packet

from .. import util
from .. import trace


class ArgumentHandler(object):
    TYPE = None

    def __init__(self, parser=None, args=None):
        self.parser = parser
        self.args = args

    @classmethod
    def instance(cls, type, *args, **kwargs):
        for c in cls.__subclasses__():
            if c.TYPE == type:
                return c(*args, **kwargs)
        raise ValueError('unknown type: %s' % type)

    def add_argument(self, type, **kwargs):
        p = self.instance(type, self.parser, self.args)
        return p.add_argument(**kwargs)

    def create_header(self, type, **kwargs):
        p = self.instance(type, self.parser, self.args)
        return p.create_header(**kwargs)


class ArgumentHandlerEntry(ArgumentHandler):
    TYPE = 'entry'

    def add_argument(self):
        self.parser.add_argument('dpid', help='datapath id to send probe')
        self.parser.add_argument('inport', help='port number to send probe')


class ArgumentHandlerRaw(ArgumentHandler):
    TYPE = 'raw'

    def add_argument(self):
        self.parser.add_argument('data', help='probe data in hexdump')

    def create_header(self):
        return self.args.data


class ArgumentHandlerEther(ArgumentHandler):
    TYPE = 'eth'

    def add_argument(self):
        self.parser.add_argument('--dst', default='52:54:00:00:00:01',
                                 help='destination MAC address')
        self.parser.add_argument('--src', default='52:54:00:00:00:02',
                                 help='source MAC address')

    def create_header(self, ethertype):
        return ryu.lib.packet.ethernet.ethernet(dst=self.args.dst,
                                                src=self.args.src,
                                                ethertype=ethertype)


class ArgumentHandlerArp(ArgumentHandler):
    TYPE = 'arp'

    def add_argument(self):
        self.parser.add_argument('--arp-tpa', default='192.168.2.1',
                                 help='target protocol address')
        self.parser.add_argument('--arp-spa', default='192.168.2.2',
                                 help='sender protocol address')
        self.parser.add_argument('--arp-tha', default='00:00:00:00:00:00',
                                 help='target hardware address')
        self.parser.add_argument('--arp-sha', default='52:54:00:00:00:02',
                                 help='sender hardware address')
        self.parser.add_argument('--arp-op', choices=('request', 'reply'),
                                 default='request', help='operation code')

    def create_header(self):
        if self.args.arp_op == 'request':
            opcode = ryu.lib.packet.arp.ARP_REQUEST
        elif self.args.arp_op == 'reply':
            opcode = ryu.lib.packet.arp.ARP_REPLY
        else:
            raise ValueError('invalid opcode: %s' % self.args.arp_op)

        return ryu.lib.packet.arp.arp_ip(opcode,
                                         self.args.arp_sha, self.args.arp_spa,
                                         self.args.arp_tha, self.args.arp_tpa)


class ArgumentHandlerIp4(ArgumentHandler):
    TYPE = 'ip4'

    def add_argument(self):
        self.parser.add_argument('--dst-ip', default='192.168.2.1',
                                 help='destination IPv4 address')
        self.parser.add_argument('--src-ip', default='192.168.2.2',
                                 help='source IPv4 address')
        self.parser.add_argument('--ip-ttl', type=int, default=255,
                                 help='IPv4 TTL')

    def create_header(self, ipproto):
        return ryu.lib.packet.ipv4.ipv4(dst=self.args.dst_ip,
                                        src=self.args.src_ip,
                                        ttl=self.args.ip_ttl,
                                        proto=ipproto)


class ArgumentHandlerIp6(ArgumentHandler):
    TYPE = 'ip6'

    def add_argument(self):
        self.parser.add_argument('--dst-ip', default='fe80::5054:ff:fe00:1',
                                 help='destination IPv6 address')
        self.parser.add_argument('--src-ip', default='fe80::5054:ff:fe00:2',
                                 help='source IPv6 address')
        self.parser.add_argument('--ip6-hop-limit', type=int, default=255,
                                 help='IPv6 hop-limit')

    def create_header(self, nxt):
        return ryu.lib.packet.ipv6.ipv6(dst=self.args.dst_ip,
                                        src=self.args.src_ip,
                                        hop_limit=self.args.ip6_hop_limit,
                                        nxt=nxt)


class ArgumentHandlerUdp(ArgumentHandler):
    TYPE = 'udp'

    def add_argument(self):
        self.parser.add_argument('--dst-port', type=int, default=4649,
                                 help='destination UDP port number')
        self.parser.add_argument('--src-port', type=int, default=37564,
                                 help='source UDP port number')

    def create_header(self):
        return ryu.lib.packet.udp.udp(dst_port=self.args.dst_port,
                                      src_port=self.args.src_port)


class ArgumentHandlerTcp(ArgumentHandler):
    TYPE = 'tcp'

    def add_argument(self):
        self.parser.add_argument('--dst-port', type=int, default=4649,
                                 help='destination TCP port number')
        self.parser.add_argument('--src-port', type=int, default=37564,
                                 help='source TCP port number')
        self.parser.add_argument('--tcp-seq', type=int, default=0,
                                 help='TCP sequence number')
        self.parser.add_argument('--tcp-ack', type=int, default=0,
                                 help='TCP acknowledgement number')
        self.parser.add_argument('--tcp-flags', default='psh',
                                 help='comma-separated mnemonic TCP flags')
        self.parser.add_argument('--tcp-window', type=int, default=0,
                                 help='TCP windows size')

    def create_header(self):
        flags = [f.strip().lower() for f in self.args.tcp_flags.split(',')]
        bits = util.tcp_flags2bits(flags)
        return ryu.lib.packet.tcp.tcp(dst_port=self.args.dst_port,
                                      src_port=self.args.src_port,
                                      seq=self.args.tcp_seq,
                                      ack=self.args.tcp_ack,
                                      bits=bits,
                                      window_size=self.args.tcp_window)


class Traceroute(util.ControlCommand):
    def dumpframe(self, data):
        parser = util.FrameParser(data)
        if parser.payload:
            raise util.InvalidFrame('payload or unsupported protocol exists: '
                                    '%s' % str(parser.payload).encode('hex'))

        self.println('Probe Data: ' + data.encode('hex'))

        for header in parser.headers:
            self.println('  ' + str(header))

        self.println('')

    def create_probe(self, data):
        path = trace.TracerouteController.PATH_PROBE
        code, body = self.client.post(path, {'data': data})

        if code != 201:
            raise RuntimeError('failed to create probe: %s' % code)

        return body['id']

    def start_probe(self, pid):
        path = trace.TracerouteController.PATH_PROBE_PID.format(pid=pid)
        code, body = self.client.put(path, {'dpid': self.args.dpid,
                                            'port': self.args.inport})
        if code != 202:
            raise RuntimeError('failed to start traceroute: %s' % code)

    def delete_probe(self, pid):
        path = trace.TracerouteController.PATH_PROBE_PID.format(pid=pid)
        code, body = self.client.delete(path)

        if code != 204:
            self.println('[WARN] failed to delete probe: %s' % code)

    def connect_websocket(self, pid=None):
        if pid is None:
            path = trace.TracerouteController.PATH_SNOOP
        else:
            path = trace.TracerouteController.PATH_SNOOP_PID.format(pid=pid)

        if self.args.port == 80:
            url = ''.join(['ws://', self.args.host, path])
        else:
            port = str(self.args.port)
            url = ''.join(['ws://', self.args.host, ':', port, path])

        return websocket.create_connection(url, timeout=self.args.timeout)

    def traceroute(self, data):
        self.dumpframe(binascii.unhexlify(data))
        pid = self.create_probe(data)
        conn = None

        try:
            stime = 0
            conn = self.connect_websocket(pid)

            self.start_probe(pid)

            for i, msg in enumerate(iter(lambda: conn.recv(), None), 1):
                msg = json.loads(msg)

                conn.send(json.dumps({
                    'id':      msg.get('id', 0),
                    'jsonrpc': msg.get('jsonrpc', '2.0'),
                    'result':  'ack',
                }))

                msg = msg['params'][0]

                if stime:
                    dtime = (msg['time'] - stime) * 1000
                else:
                    dtime = 0
                    stime = msg['time']

                self.println('%3d  %s:%s  %.3f ms' %
                             (i, msg['dpid'], msg['port'], dtime))

                if not msg['loop']:
                    continue

                self.println('************* LOOP DETECTED *************')
                raise StopIteration()

        except websocket.WebSocketTimeoutException:
            pass
        except KeyboardInterrupt:
            self.println('')
        except StopIteration:
            pass
        finally:
            if conn:
                conn.close()
            self.delete_probe(pid)

    @classmethod
    def subcmd_raw(cls, subcmd):
        parser = subcmd.add_parser('raw', help='send raw probe')
        handler = ArgumentHandler(parser=parser)
        handler.add_argument('entry')
        handler.add_argument('raw')

    def handle_raw(self):
        handler = ArgumentHandler(args=self.args)
        header = handler.create_header('raw')
        self.traceroute(header)

    @classmethod
    def subcmd_arp(cls, subcmd):
        parser = subcmd.add_parser('arp', help='send ARP probe')
        handler = ArgumentHandler(parser=parser)
        handler.add_argument('eth')
        handler.add_argument('arp')
        handler.add_argument('entry')

    def handle_arp(self):
        ethertype = ryu.lib.packet.ether_types.ETH_TYPE_ARP
        handler = ArgumentHandler(args=self.args)
        eth = handler.create_header('eth', ethertype=ethertype)
        arp = handler.create_header('arp')
        header = eth / arp
        header.serialize()
        self.traceroute(str(header.data).encode('hex'))

    @classmethod
    def subcmd_udp4(cls, subcmd):
        parser = subcmd.add_parser('udp4', help='send UDP(IPv4) probe')
        handler = ArgumentHandler(parser=parser)
        handler.add_argument('eth')
        handler.add_argument('ip4')
        handler.add_argument('udp')
        handler.add_argument('entry')

    def handle_udp4(self):
        ethertype = ryu.lib.packet.ether_types.ETH_TYPE_IP
        handler = ArgumentHandler(args=self.args)
        eth = handler.create_header('eth', ethertype=ethertype)
        ip4 = handler.create_header('ip4', ipproto=socket.IPPROTO_UDP)
        udp = handler.create_header('udp')
        header = eth / ip4 / udp
        header.serialize()
        self.traceroute(str(header.data).encode('hex'))

    @classmethod
    def subcmd_tcp4(cls, subcmd):
        parser = subcmd.add_parser('tcp4', help='send TCP(IPv4) probe')
        handler = ArgumentHandler(parser=parser)
        handler.add_argument('eth')
        handler.add_argument('ip4')
        handler.add_argument('tcp')
        handler.add_argument('entry')

    def handle_tcp4(self):
        ethertype = ryu.lib.packet.ether_types.ETH_TYPE_IP
        handler = ArgumentHandler(args=self.args)
        eth = handler.create_header('eth', ethertype=ethertype)
        ip4 = handler.create_header('ip4', ipproto=socket.IPPROTO_TCP)
        tcp = handler.create_header('tcp')
        header = eth / ip4 / tcp
        header.serialize()
        self.traceroute(str(header.data).encode('hex'))

    @classmethod
    def subcmd_udp6(cls, subcmd):
        parser = subcmd.add_parser('udp6', help='send UDP(IPv6) probe')
        handler = ArgumentHandler(parser=parser)
        handler.add_argument('eth')
        handler.add_argument('ip6')
        handler.add_argument('udp')
        handler.add_argument('entry')

    def handle_udp6(self):
        ethertype = ryu.lib.packet.ether_types.ETH_TYPE_IPV6
        handler = ArgumentHandler(args=self.args)
        eth = handler.create_header('eth', ethertype=ethertype)
        ip6 = handler.create_header('ip6', nxt=socket.IPPROTO_UDP)
        udp = handler.create_header('udp')
        header = eth / ip6 / udp
        header.serialize()
        self.traceroute(str(header.data).encode('hex'))

    @classmethod
    def subcmd_tcp6(cls, subcmd):
        parser = subcmd.add_parser('tcp6', help='send TCP(IPv6) probe')
        handler = ArgumentHandler(parser=parser)
        handler.add_argument('eth')
        handler.add_argument('ip6')
        handler.add_argument('tcp')
        handler.add_argument('entry')

    def handle_tcp6(self):
        ethertype = ryu.lib.packet.ether_types.ETH_TYPE_IPV6
        handler = ArgumentHandler(args=self.args)
        eth = handler.create_header('eth', ethertype=ethertype)
        ip6 = handler.create_header('ip6', nxt=socket.IPPROTO_TCP)
        tcp = handler.create_header('tcp')
        header = eth / ip6 / tcp
        header.serialize()
        self.traceroute(str(header.data).encode('hex'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1',
                        help='controller host')
    parser.add_argument('--port', type=int, default=8080,
                        help='controller port')
    parser.add_argument('--timeout', type=float, default=2.0,
                        help='timeout in seconds')
    try:
        Traceroute.register_subcommand(parser.add_subparsers(dest='subcmd'))
        Traceroute.run(parser.parse_args())
    except Exception as e:
        parser.error('%s: %s' % (type(e).__name__, str(e)))


if __name__ == '__main__':
    main()
