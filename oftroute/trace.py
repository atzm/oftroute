# -*- coding: utf-8 -*-

import time
import json
import logging
import binascii
import contextlib

import webob

import ryu.app.wsgi
import ryu.base.app_manager

import ryu.topology.event
import ryu.controller.handler

import ryu.lib.dpid

from . import util
from . import rule
from . import event
from . import config

_logger = logging.getLogger(__name__)


class ProbeEntry(list):
    def __init__(self, id, data, init=[]):
        super(ProbeEntry, self).__init__(init)
        self.id = id
        self.data = data
        self.created = time.time()
        self.used = 0

    def reset(self):
        self[:] = []
        return self

    def has(self, **entry):
        for e in self:
            for k, v in entry.iteritems():
                if e.get(k) != v:
                    break
            else:
                return True
        return False


class TracerouteApp(event.ExceptionHandlerMixIn, ryu.base.app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi':  ryu.app.wsgi.WSGIApplication,
    }
    PID_MAX = (1 << 64) - 1

    def __init__(self, *args, **kwargs):
        super(TracerouteApp, self).__init__(*args, **kwargs)

        self.listener = {}  # key:None is the global listener
        self.probe = {}
        self.pid = 0
        self.rule = rule.getclass(config.ruleclass())()

        kwargs['wsgi'].register(TracerouteController, {'app': self})

    @ryu.controller.handler.set_ev_cls(event.EventProbeIn)
    def handle_probe_in(self, ev):
        try:
            probe = self.get_probe(ev.id)
        except KeyError:
            _logger.warning('untracked frame: %s', ev.data.encode('hex'))
            return

        dpid = '%016x' % ev.dpid
        port = '%08x' % ev.port
        msg = {
            'id':   '%016x' % ev.id,
            'time': ev.time,
            'dpid': dpid,
            'port': port,
            'data': ev.data.encode('hex'),
            'loop': probe.has(dpid=dpid, port=port),
        }

        probe.append(msg)
        self.notify_listener('ProbeIn', ev.id, msg)

        if msg['loop']:
            _logger.info('stop probe chain by loop: %s' % json.dumps(msg))
        else:
            self.send_probe_out(ev.dpid, ev.port, ev.data, True)

    def start_probe_out(self, pid, dpid, port):
        probe = self.get_probe(pid)
        if probe.used != 0:
            raise ValueError('probe already used: %016x' % pid)
        probe.reset()
        probe.used = time.time()
        data = binascii.unhexlify(probe.data)
        self.send_probe_out(dpid, port, data, False)

    def send_probe_out(self, dpid, port, data, metadata):
        req = event.EventProbeOutRequest(dpid, port, data, metadata)
        self.send_request(req)

    def get_probe(self, pid):
        return self.probe[pid]

    def list_probe(self, pid_list=[]):
        if pid_list:
            return [v for k, v in self.probe.iteritems() if k in pid_list]
        else:
            return self.probe.values()

    def get_flow(self, dpid):
        reply = self.send_request(event.EventFlowGetRequest(dpid))
        return reply.flows

    def add_flow(self, dpid, entry):
        self.send_request(event.EventFlowAddRequest(dpid, entry))

    def del_flow(self, dpid, entry):
        self.send_request(event.EventFlowDelRequest(dpid, entry))

    def get_switch(self, dpid=None):
        reply = self.send_request(ryu.topology.event.EventSwitchRequest(dpid))
        return [sw.to_dict() for sw in reply.switches]

    def register_probe(self, data):
        data = binascii.unhexlify(data)

        try:
            data = self.rule.create_frame(data, self.pid)
            self.probe[self.pid] = ProbeEntry(self.pid, data.encode('hex'))
            return self.pid
        finally:
            self.pid += 1
            self.pid &= self.PID_MAX

    def unregister_probe(self, pid):
        return self.probe.pop(pid)

    @contextlib.contextmanager
    def listen(self, ws, pid=None):
        client = ryu.app.wsgi.WebSocketRPCClient(ws)
        try:
            self.register_listener(client, pid)
            yield client
        finally:
            self.unregister_listener(client, pid)

    def register_listener(self, listener, pid=None):
        self.listener.setdefault(pid, []).append(listener)

    def unregister_listener(self, listener, pid=None):
        try:
            self.listener.setdefault(pid, []).remove(listener)
        except ValueError:
            pass

    def notify_listener(self, name, pid, msg):
        def get_listener(pid):
            list_ = self.listener.get(pid, [])
            return zip(list_, [pid] * len(list_))

        for listener, pid in get_listener(None) + get_listener(pid):
            try:
                getattr(listener.get_proxy(prefix='oftroute.'), name)(msg)
            except:
                _logger.exception(str(listener))
                self.unregister_listener(listener, pid)


class TracerouteController(ryu.app.wsgi.ControllerBase):
    PATH_BASE = '/oftroute'
    PATH_SNOOP = '/'.join([PATH_BASE, 'snoop'])
    PATH_SNOOP_PID = '/'.join([PATH_SNOOP, '{pid}'])
    PATH_PROBE = '/'.join([PATH_BASE, 'probes'])
    PATH_PROBE_PID = '/'.join([PATH_PROBE, '{pid}'])
    PATH_SWITCHES = '/'.join([PATH_BASE, 'switches'])
    PATH_SWITCHES_DPID = '/'.join([PATH_SWITCHES, '{dpid}'])
    PATH_SWITCHES_FLOW = '/'.join([PATH_SWITCHES_DPID, 'flows'])

    def __init__(self, req, link, data, **conf):
        super(TracerouteController, self).__init__(req, link, data, **conf)
        self.app = data.get('app')

    @ryu.app.wsgi.websocket('snoop_all', PATH_SNOOP)
    def snoop_all(self, ws):
        with self.app.listen(ws) as client:
            client.serve_forever()

    @ryu.app.wsgi.websocket('snoop', PATH_SNOOP_PID)
    def snoop(self, ws):
        pid = ws.environ['wsgiorg.routing_args'][1]['pid']
        if not util.PROBE_ID_REGEX.match(pid):
            return

        pid = int(pid, 16)
        with self.app.listen(ws, pid) as client:
            client.serve_forever()

    @ryu.app.wsgi.route('probes_post', PATH_PROBE, methods=['POST'])
    def probes_post(self, req, **kwargs):
        try:
            body = json.loads(req.body)
            pid = self.app.register_probe(body['data'])
        except:
            _logger.exception('invalid request')
            return webob.response.Response(status=400)

        pid = '%016x' % pid
        location = self.PATH_PROBE_PID.format(pid=pid)
        body = json.dumps({'id': pid})
        headers = dict(Location=location, **util.CTYPE_JSON)
        return webob.response.Response(status=201, body=body, headers=headers)

    @ryu.app.wsgi.route('probes_list', PATH_PROBE, methods=['GET'])
    def probes_list(self, req, **kwargs):
        @util.listify
        def makebody(probe_list):
            for p in probe_list:
                yield {
                    'id':      '%016x' % p.id,
                    'created': p.created,
                    'used':    p.used,
                    'data':    p.data,
                }

        pid_list = []
        for pid in req.params.getall('id'):
            if not util.PROBE_ID_REGEX.match(pid):
                return webob.response.Response(status=400)
            pid_list.append(int(pid))

        body = makebody(self.app.list_probe(pid_list))
        return webob.response.Response(status=200, body=json.dumps(body),
                                       headers=util.CTYPE_JSON)

    @ryu.app.wsgi.route('probes_put', PATH_PROBE_PID, methods=['PUT'],
                        requirements={'pid': util.PROBE_ID_PATTERN})
    def probes_put(self, req, pid, **kwargs):
        pid = int(pid, 16)

        try:
            self.app.get_probe(pid)
        except KeyError:
            return webob.response.Response(status=404)

        try:
            body = json.loads(req.body)
            dpid = int(body['dpid'], 16)
            port = int(body['port'], 16)
            self.app.start_probe_out(pid, dpid, port)
        except:
            _logger.exception('invalid request')
            return webob.response.Response(status=400)

        return webob.response.Response(status=202,
                                       headers={'Location': req.path})

    @ryu.app.wsgi.route('probes_get', PATH_PROBE_PID, methods=['GET'],
                        requirements={'pid': util.PROBE_ID_PATTERN})
    def probes_get(self, req, pid, **kwargs):
        try:
            probe = self.app.get_probe(int(pid, 16))
        except KeyError:
            return webob.response.Response(status=404)

        body = json.dumps(list(probe))
        return webob.response.Response(status=200, body=body,
                                       headers=util.CTYPE_JSON)

    @ryu.app.wsgi.route('probes_del', PATH_PROBE_PID, methods=['DELETE'],
                        requirements={'pid': util.PROBE_ID_PATTERN})
    def probes_del(self, req, pid, **kwargs):
        try:
            self.app.unregister_probe(int(pid, 16))
        except KeyError:
            return webob.response.Response(status=404)
        return webob.response.Response(status=204)

    @ryu.app.wsgi.route('switches_getall', PATH_SWITCHES, methods=['GET'])
    def switches_getall(self, req, **kwargs):
        body = json.dumps(self.app.get_switch())
        return webob.response.Response(status=200, body=body,
                                       headers=util.CTYPE_JSON)

    @ryu.app.wsgi.route('switches_get', PATH_SWITCHES_DPID,
                        methods=['GET'],
                        requirements={'dpid': ryu.lib.dpid.DPID_PATTERN})
    def switches_get(self, req, dpid, **kwargs):
        sw = self.app.get_switch(int(dpid, 16))
        if not sw:
            return webob.response.Response(status=404)

        return webob.response.Response(status=200, body=json.dumps(sw[0]),
                                       headers=util.CTYPE_JSON)

    @ryu.app.wsgi.route('flows_get', PATH_SWITCHES_FLOW, methods=['GET'],
                        requirements={'dpid': ryu.lib.dpid.DPID_PATTERN})
    def flows_get(self, req, dpid, **kwargs):
        dpid = int(dpid, 16)
        if not self.app.get_switch(dpid):
            return webob.response.Response(status=404)

        try:
            body = json.dumps(self.app.get_flow(dpid))
        except:
            _logger.exception('failed to get flow entries')
            return webob.response.Response(status=400)

        return webob.response.Response(status=200, body=body,
                                       headers=util.CTYPE_JSON)

    @ryu.app.wsgi.route('flows_put', PATH_SWITCHES_FLOW, methods=['PUT'],
                        requirements={'dpid': ryu.lib.dpid.DPID_PATTERN})
    def flows_put(self, req, dpid, **kwargs):
        dpid = int(dpid, 16)
        if not self.app.get_switch(dpid):
            return webob.response.Response(status=404)

        try:
            self.app.add_flow(dpid, self._extract_flow_entry(req))
        except:
            _logger.exception('failed to add flow entry')
            return webob.response.Response(status=400)

        return webob.response.Response(status=204)

    @ryu.app.wsgi.route('flows_del', PATH_SWITCHES_FLOW, methods=['DELETE'],
                        requirements={'dpid': ryu.lib.dpid.DPID_PATTERN})
    def flows_del(self, req, dpid, **kwargs):
        # DELETE method with request body is not standard,
        # but flow entry does not have the unique identifier.
        # Also cookie may be used for other intentions.

        dpid = int(dpid, 16)
        if not self.app.get_switch(dpid):
            return webob.response.Response(status=404)

        try:
            self.app.del_flow(dpid, self._extract_flow_entry(req))
        except:
            _logger.exception('failed to delete flow entry')
            return webob.response.Response(status=400)

        return webob.response.Response(status=204)

    @staticmethod
    def _extract_flow_entry(req):
        body = json.loads(req.body)
        if not isinstance(body, dict):
            raise ValueError(body)
        if 'entry' not in body:
            raise ValueError(body)
        if not isinstance(body['entry'], basestring):
            raise ValueError(body)
        return body['entry']
