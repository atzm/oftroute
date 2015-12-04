# -*- coding: utf-8 -*-

import struct

from ryu import utils
from ryu.ofproto import ofproto_parser as ofproto_parser_common
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as ofproto_parser

from ofpstr import ofp4


class OFPFlowMod(ofproto_parser.OFPFlowMod):
    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPFlowMod, cls).parser(datapath, version, msg_type,
                                            msg_len, xid, buf)
        offset = ofproto.OFP_HEADER_SIZE

        (msg.cookie,
         msg.cookie_mask,
         msg.table_id,
         msg.command,
         msg.idle_timeout,
         msg.hard_timeout,
         msg.priority,
         msg.buffer_id,
         msg.out_port,
         msg.out_group,
         msg.flags) = struct.unpack_from(ofproto.OFP_FLOW_MOD_PACK_STR0,
                                         msg.buf, offset)
        offset += struct.calcsize(ofproto.OFP_FLOW_MOD_PACK_STR0)

        msg.match = ofproto_parser.OFPMatch.parser(msg.buf, offset)
        padding_length = utils.round_up(msg.match.length, 8) - msg.match.length
        offset += msg.match.length + padding_length

        msg.instructions = []
        while msg_len > offset:
            inst = ofproto_parser.OFPInstruction.parser(msg.buf, offset)
            msg.instructions.append(inst)
            offset += inst.len

        return msg


def flowfilter(entry, rules={}):
    items = []

    for item in entry.split(','):
        item = item.strip()

        try:
            key, val = item.split('=', 1)

            if rules.get(key, lambda x: False)(val):
                continue

        except ValueError:
            pass

        items.append(item)

    return ','.join(items)


def str2mod(dp, line, cmd):
    buf = ofp4.str2mod(line, cmd=cmd)
    (version, msg_type, msg_len, xid) = ofproto_parser_common.header(buf)
    return OFPFlowMod.parser(dp, version, msg_type, msg_len, None, buf)


def mod2str(msg):
    assert isinstance(msg, ofproto_parser.OFPFlowMod)
    msg.serialize()
    return ofp4.mod2str(msg.buf)


def stats2str(dp, stats):
    assert isinstance(stats, ofproto_parser.OFPFlowStats)
    duration = stats.duration_sec + (stats.duration_nsec / 1000000000.0)
    msg = OFPFlowMod(dp, stats.cookie, 0, stats.table_id, 0,
                     stats.idle_timeout, stats.hard_timeout, stats.priority,
                     0, 0, 0, stats.flags, stats.match, stats.instructions)
    return ', '.join([
        'duration=%.3fs' % duration,
        'n_packets=%d' % stats.packet_count,
        'n_bytes=%d' % stats.byte_count,
        flowfilter(mod2str(msg), {'buffer': lambda v: int(v, 16) == 0}),
    ])
