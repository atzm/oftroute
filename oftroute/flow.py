# -*- coding: utf-8 -*-

import time
import logging

import ryu.base.app_manager

import ryu.controller.handler
import ryu.controller.ofp_event

import ryu.topology.event
import ryu.app.ofctl.api

import ryu.ofproto.ofproto_v1_3

from . import util
from . import rule
from . import event
from . import config
from .ofparser import flowmod_parser_v1_3

_logger = logging.getLogger(__name__)


class Ofctl(object):
    FLOWMOD = {
        ryu.ofproto.ofproto_v1_3.OFP_VERSION: flowmod_parser_v1_3,
    }

    def __init__(self, app, dp):
        self.app = app
        self.dp = dp

    @property
    def ofproto(self):
        return self.dp.ofproto

    @property
    def parser(self):
        return self.dp.ofproto_parser

    @property
    def ofpver(self):
        return self.ofproto.OFP_VERSION

    @property
    def flowmod(self):
        return self.FLOWMOD.get(self.ofpver)

    def send_msg(self, msg, reply=None, multi=False):
        return ryu.app.ofctl.api.send_msg(self.app, msg, reply, multi)

    def flow_filter(self, msg):
        # TODO: flow entry that matches the probe rule should be filtered
        if self.app.cookie and self.app.cookie == msg.cookie:
            return None
        if msg.table_id in (self.app.FLOW_TABLE_ID, self.ofproto.OFPTT_ALL) \
           and msg.priority >= self.app.FLOW_PRIORITY:
            return None
        return msg

    @util.listify
    def dump_flows(self, raw=True):
        if not self.flowmod:
            _logger.error('unsupported protocol version: 0x%x', self.ofpver)
            raise StopIteration()

        req = self.parser.OFPFlowStatsRequest(
            self.dp, 0, self.ofproto.OFPTT_ALL, self.ofproto.OFPP_ANY,
            self.ofproto.OFPG_ANY, 0, 0, self.parser.OFPMatch())

        msgs = self.send_msg(req, self.parser.OFPFlowStatsReply, True)

        for msg in msgs:
            for stats in msg.body:
                stats = stats if raw else self.flow_filter(stats)
                if stats:
                    yield self.flowmod.stats2str(self.dp, stats)

    def mod_flow(self, entry, cmd, raw=True):
        if not self.flowmod:
            _logger.error('unsupported protocol version: 0x%x', self.ofpver)
            return False

        msg = self.flowmod.str2mod(self.dp, entry, cmd)
        msg = msg if raw else self.flow_filter(msg)

        if msg:
            self.send_msg(msg)
            return True

        return False

    def add_flow(self, entry, raw=True):
        return self.mod_flow(entry, self.ofproto.OFPFC_ADD, raw)

    def del_flows(self, entry, raw=True):
        return self.mod_flow(entry, self.ofproto.OFPFC_DELETE_STRICT, raw)


class FlowManager(event.ExceptionHandlerMixIn, ryu.base.app_manager.RyuApp):
    OFP_VERSIONS = [
        ryu.ofproto.ofproto_v1_3.OFP_VERSION,
    ]
    _EVENTS = [
        event.EventProbeIn,
    ]
    FLOW_TABLE_ID = 0
    FLOW_PRIORITY = 0xffff

    def __init__(self, *args, **kwargs):
        super(FlowManager, self).__init__(*args, **kwargs)
        self.rule = rule.getclass(config.ruleclass())()
        self.cookie = config.cookie()
        self.metafield = config.metafield()
        self.metavalue = config.metavalue()

    def get_datapath(self, dpid):
        rep = self.send_request(ryu.topology.event.EventSwitchRequest(dpid))
        if len(rep.switches) != 1:
            raise ValueError(dpid)
        return rep.switches[0].dp

    def send_probe_out(self, dp, port, data, metadata):
        actions = [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_TABLE)]
        if metadata:
            setfield = {self.metafield: self.metavalue}
            actions.insert(0, dp.ofproto_parser.OFPActionSetField(**setfield))

        msg = dp.ofproto_parser.OFPPacketOut(dp, dp.ofproto.OFP_NO_BUFFER,
                                             port, actions, data)
        return Ofctl(self, dp).send_msg(msg)

    @ryu.controller.handler.set_ev_cls(
        [ryu.controller.ofp_event.EventOFPPacketIn],
        ryu.controller.handler.MAIN_DISPATCHER)
    def handle_packet_in(self, ev):
        now = time.time()

        msg = ev.msg
        dp = msg.datapath
        port = msg.match['in_port']
        metadata = msg.match.get(self.metafield)

        if self.cookie and self.cookie != msg.cookie:
            # assume this packet-in message came by user flow entry
            return
        if metadata == self.metavalue:
            _logger.error('packet-in with reserved value: %s=0x%016x',
                          self.metafield, self.metavalue)
            return
        if msg.table_id != self.FLOW_TABLE_ID or \
           msg.reason != dp.ofproto.OFPR_ACTION:
            _logger.warning('unexpected packet-in: table_id=%d, reason=%d',
                            msg.table_id, msg.reason)
            return
        try:
            pid = self.rule.parse_frame(msg.data)
        except util.InvalidFrame as e:
            _logger.warning(str(e))
            return

        probe_in = event.EventProbeIn(now, pid, dp.id, port, msg.data)
        self.send_event_to_observers(probe_in)

    @ryu.controller.handler.set_ev_cls(ryu.topology.event.EventSwitchEnter)
    def handle_switch_enter(self, ev):
        def get_match(**kwargs):
            m = ','.join('%s=%s' % (k, v) for k, v in kwargs.iteritems())
            return ','.join([m, self.rule.get_match()])

        extmatch = {'cookie': self.cookie} if self.cookie else {}
        extmatch.update(**{self.metafield: 0})
        match = get_match(table=self.FLOW_TABLE_ID,
                          priority=self.FLOW_PRIORITY, **extmatch)

        buflen = getattr(ev.switch.dp.ofproto, 'OFPCML_NO_BUFFER', 0xffff)
        action = '@apply,output=controller:0x%x' % buflen

        ofctl = Ofctl(self, ev.switch.dp)
        ofctl.add_flow(','.join([match, action]))

    @ryu.controller.handler.set_ev_cls(event.EventProbeOutRequest)
    def handle_probe_out(self, req):
        with self.send_reply(req, event.EventProbeOutReply):
            dp = self.get_datapath(req.dpid)
            self.send_probe_out(dp, req.port, req.data, req.metadata)

    @ryu.controller.handler.set_ev_cls(event.EventFlowGetRequest)
    def handle_flow_get(self, req):
        with self.send_reply(req, event.EventFlowGetReply) as rep:
            dp = self.get_datapath(req.dpid)
            rep.flows = Ofctl(self, dp).dump_flows(False)

    @ryu.controller.handler.set_ev_cls(event.EventFlowAddRequest)
    def handle_flow_add(self, req):
        with self.send_reply(req, event.EventFlowAddReply):
            dp = self.get_datapath(req.dpid)
            if not Ofctl(self, dp).add_flow(req.entry, False):
                raise ValueError(req.entry)

    @ryu.controller.handler.set_ev_cls(event.EventFlowDelRequest)
    def handle_flow_del(self, req):
        with self.send_reply(req, event.EventFlowDelReply):
            dp = self.get_datapath(req.dpid)
            if not Ofctl(self, dp).del_flows(req.entry, False):
                raise ValueError(req.entry)


ryu.base.app_manager.require_app('ryu.topology.switches')
