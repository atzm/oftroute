# -*- coding: utf-8 -*-

import logging
import contextlib

import ryu.controller.event

_logger = logging.getLogger(__name__)


class ExceptionHandlerMixIn(object):
    def send_request(self, *args, **kwargs):
        rep = super(ExceptionHandlerMixIn, self).send_request(*args, **kwargs)
        if isinstance(getattr(rep, 'exception', None), Exception):
            raise rep.exception
        return rep

    @contextlib.contextmanager
    def send_reply(self, req, cls, *args, **kwargs):
        rep = cls(req.src, *args, **kwargs)
        try:
            yield rep
        except Exception as e:
            rep.exception = e
            _logger.debug(e, exc_info=True)
        self.reply_to_request(req, rep)


class ExceptionMixIn(object):
    def __init__(self, *args, **kwargs):
        super(ExceptionMixIn, self).__init__(*args, **kwargs)
        self.exception = None


class EventProbeIn(ryu.controller.event.EventBase):
    def __init__(self, time, id, dpid, port, data):
        super(EventProbeIn, self).__init__()
        self.time = time
        self.id = id
        self.dpid = dpid
        self.port = port
        self.data = data


class EventProbeOutRequest(ryu.controller.event.EventRequestBase):
    def __init__(self, dpid, port, data, metadata):
        super(EventProbeOutRequest, self).__init__()
        self.dst = 'FlowManager'
        self.dpid = dpid
        self.port = port
        self.data = data
        self.metadata = metadata


class EventProbeOutReply(ryu.controller.event.EventReplyBase, ExceptionMixIn):
    pass


class EventFlowGetRequest(ryu.controller.event.EventRequestBase):
    def __init__(self, dpid):
        super(EventFlowGetRequest, self).__init__()
        self.dst = 'FlowManager'
        self.dpid = dpid


class EventFlowGetReply(ryu.controller.event.EventReplyBase, ExceptionMixIn):
    def __init__(self, dst, flows=[]):
        super(EventFlowGetReply, self).__init__(dst)
        self.flows = flows


class EventFlowAddRequest(ryu.controller.event.EventRequestBase):
    def __init__(self, dpid, entry):
        super(EventFlowAddRequest, self).__init__()
        self.dst = 'FlowManager'
        self.dpid = dpid
        self.entry = entry


class EventFlowAddReply(ryu.controller.event.EventReplyBase, ExceptionMixIn):
    pass


class EventFlowDelRequest(EventFlowAddRequest):
    pass


class EventFlowDelReply(EventFlowAddReply):
    pass
