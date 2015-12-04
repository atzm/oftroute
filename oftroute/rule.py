# -*- coding: utf-8 -*-

import abc
import struct
import inspect
import functools

import ryu.lib.packet

from . import util


class RuleBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_match(self):
        pass

    @abc.abstractmethod
    def create_frame(self, data, pid):
        pass

    @abc.abstractmethod
    def parse_frame(self, data):
        pass


class RuleVlan(RuleBase):
    VID = 0
    PCP = 0

    def get_match(self):
        mask = 0xffff if self.VID else 0x1000  # VID=0 matches any VIDs
        return 'vlan_vid=0x%04x/0x%04x,vlan_pcp=%d' % \
            (0x1000 | self.VID, mask, self.PCP)

    def create_frame(self, data, pid):
        def inject(payload, parser=ryu.lib.packet.ethernet.ethernet):
            eth, parser, payload = parser.parser(payload)

            if issubclass(parser, ryu.lib.packet.vlan.svlan):
                raise util.InvalidFrame('unsupported: IEEE 802.1ad')

            elif issubclass(parser, ryu.lib.packet.vlan.vlan):
                vlh, parser, payload = parser.parser(payload)
                self.check_header(vlh)

            else:
                vlh = ryu.lib.packet.vlan.vlan(vid=self.VID, pcp=self.PCP,
                                               ethertype=eth.ethertype)
                eth.ethertype = ryu.lib.packet.ether_types.ETH_TYPE_8021Q

            yield eth
            yield vlh

            parser = util.FrameParser(payload, parser)
            for header in parser.headers:
                yield parser.cleanup(header)

        try:
            buf = functools.reduce(lambda x, y: x / y, inject(data))
            buf /= struct.pack('!Q', pid)
            buf.serialize()
            return str(buf.data)
        except Exception as e:
            raise util.InvalidFrame('parse error: %s: %s: %s' %
                                    (type(e).__name__, str(e),
                                     data.encode('hex')))

    def parse_frame(self, data):
        try:
            parser = util.FrameParser(data)
        except:
            raise util.InvalidFrame('parse error: %s' % data.encode('hex'))

        vlh = parser.find(ryu.lib.packet.vlan.vlan)
        if vlh:
            self.check_header(vlh)
        else:
            raise util.InvalidFrame('no 802.1Q found: %s' % data.encode('hex'))

        if len(parser.payload) != 8:
            payload = parser.payload.encode('hex')
            raise util.InvalidFrame('invalid payload: %s' % payload)

        return struct.unpack('!Q', parser.payload)[0]

    def check_header(self, header):
        if type(header) is not ryu.lib.packet.vlan.vlan:
            raise util.InvalidFrame('invalid type: %s' % type(header).__name__)

        #   VID SELECTION RULE
        # ----------------------
        #  rule | post | result
        #     0 |    0 |      0
        #     0 |  100 |    100  <-- prioritize the post.
        #   100 |  100 |    100      because the rule VID 0 means
        #   100 |    0 |     NG      just OFPVID_PRESENT.
        #   100 |  101 |     NG
        if self.VID and header.vid != self.VID:
            raise util.InvalidFrame('VID mismatch: %d/%d' %
                                    (self.VID, header.vid))

        #   PCP SELECTION RULE
        # ----------------------
        #  rule | post | result
        #     0 |    0 |      0
        #     0 |    7 |     NG  <-- PCP only allows perfect matching.
        #     7 |    7 |      7
        #     7 |    0 |     NG
        #     7 |    6 |     NG
        if header.pcp != self.PCP:
            raise util.InvalidFrame('PCP mismatch: %d/%d' %
                                    (self.PCP, header.pcp))


for _pcp in range(8):
    _name = 'RuleVlanPcp%d' % _pcp
    globals()[_name] = type(_name, (RuleVlan,), {'PCP': _pcp})


def getclass(name):
    cls = globals().get(name)
    if inspect.isclass(cls) and issubclass(cls, RuleBase):
        return cls
    raise ValueError(name)
