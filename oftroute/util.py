# -*- coding: utf-8 -*-

from __future__ import print_function

import re
import sys
import json
import email
import urllib
import urllib2
import inspect
import functools

import ryu.lib.packet

CTYPE_JSON = {'Content-type': 'application/json'}
PROBE_ID_PATTERN = r'[0-9a-f]{16}'
PROBE_ID_REGEX = re.compile(PROBE_ID_PATTERN)


def listify(func):
    @functools.wraps(func)
    def _(*args, **kwargs):
        return list(func(*args, **kwargs))
    return _


def tcp_flags2bits(flags):
    bits = 0
    allflags = ('fin', 'syn', 'rst', 'psh', 'ack', 'urg')

    flagset = set(flags)
    allset = set(allflags)

    if not (flagset <= allset):
        raise ValueError('unsupported flags: %s' % ', '.join(flagset - allset))

    for n, flag in enumerate(allflags):
        if flag in flags:
            bits |= 1 << n

    return bits


class InvalidFrame(Exception):
    pass


class FrameParser(object):
    def __init__(self, data, parser=ryu.lib.packet.ethernet.ethernet):
        self._data = data
        self._parser = parser
        self.parse()

    def parse(self):
        payload = self._data
        parser = self._parser
        self._headers = []
        while parser and payload:
            header, parser, payload = parser.parser(payload)
            self._headers.append(header)
        self._payload = str(payload)

    @property
    def headers(self):
        return self._headers

    @property
    def payload(self):
        return self._payload

    def find(self, parser):
        for header in self.headers:
            if type(header) is parser:
                return header
        return None

    @staticmethod
    def cleanup(header):
        # ipv4, udp, ...
        if hasattr(header, 'total_length'):
            header.total_length = 0

        # ipv6, ...
        if hasattr(header, 'payload_length'):
            header.payload_length = 0

        # ipv4, udp, tcp, icmp, icmpv6, ...
        if hasattr(header, 'csum'):
            header.csum = 0

        return header


class ControlCommand(object):
    def __init__(self, args, fp=sys.stdout):
        self.args = args
        self.fp = fp
        self.client = HTTPClient(args.host, args.port)

    @classmethod
    def register_subcommand(cls, subcmd):
        for name, member in inspect.getmembers(cls):
            if name.startswith('subcmd_') and inspect.ismethod(member):
                member(subcmd)

    @classmethod
    def run(cls, args, **opts):
        self = cls(args, **opts)
        return getattr(self, 'handle_%s' % args.subcmd.replace('-', '_'))()

    def println(self, *args, **kwargs):
        print(*args, file=self.fp, **kwargs)


class HTTPClient(object):
    def __init__(self, host, port, https=False, charset='utf-8'):
        self.host = str(host)
        self.port = str(port)
        self.https = bool(https)
        self.charset = str(charset)
        self.content_handler = {}
        self.set_content_handler('application/json', json.loads)

    def set_content_handler(self, ctype, func):
        self.content_handler[ctype] = func

    def get_content_handler(self, ctype, default=lambda x: x):
        return self.content_handler.get(ctype, default)

    def del_content_handler(self, ctype):
        self.content_handler.pop(ctype, None)

    def get(self, path, **query):
        return self.request('GET', path, query=query)

    def put(self, path, body, **query):
        return self.request('PUT', path, body=body, query=query)

    def post(self, path, body, **query):
        return self.request('POST', path, body=body, query=query)

    def delete(self, path, body=None, **query):
        return self.request('DELETE', path, body=body, query=query)

    def request(self, method, path, body=None, query={}, headers={}):
        if body is not None:
            body = json.dumps(body, ensure_ascii=False).encode(self.charset)
            ctype = 'application/json; charset=%s' % self.charset.upper()
            headers = headers.copy()
            headers['Content-Type'] = ctype

        try:
            url = self.url(path, query)
            code, info, body = self._request(method, url, body, headers)
            return code, self._parsebody(''.join(info.headers), body)
        except urllib2.HTTPError as e:
            return e.getcode(), ''

    def _request(self, method, url, body, headers={}):
        req = urllib2.Request(url, body, headers)
        req.get_method = lambda: str(method)
        obj = urllib2.urlopen(req)
        return obj.getcode(), obj.info(), obj.read()

    def _parsebody(self, strhdr, body):
        message = email.message_from_string(strhdr)
        ctype = message.get_content_type()
        charset = message.get_content_charset() or self.charset
        body = unicode(body, charset, 'replace')
        return self.get_content_handler(ctype)(body)

    def url(self, path, query={}):
        if self.https:
            scheme = 'https'
            default_port = '443'
        else:
            scheme = 'http'
            default_port = '80'

        if default_port == self.port:
            parts = [scheme, '://', self.host, path]
        else:
            parts = [scheme, '://', self.host, ':', self.port, path]

        if query:
            parts.extend(['?', self.querystring(query)])

        return str(''.join(parts))

    def querystring(self, query):
        q = {}
        for k, v in query.iteritems():
            if type(k) == unicode:
                k = k.encode(self.charset)
            if type(v) == unicode:
                v = v.encode(self.charset)
            q[k] = v
        return urllib.urlencode(q)
