# -*- coding: utf-8 -*-

import argparse

import ofpstr.ofp4

from .. import util
from .. import trace


class Ofctl(util.ControlCommand):
    def dump_datapath(self, entry):
        self.println('Bridge "%s"' % entry['dpid'])

        for port in entry['ports']:
            self.println('  Port "%s"' % port['name'])
            self.println('    PortNum: "%s"' % port['port_no'])
            self.println('    Address: "%s"' % port['hw_addr'])

        self.println('')

    @classmethod
    def subcmd_list(cls, subcmd):
        p = subcmd.add_parser('list', help='list all datapath')
        return p

    def handle_list(self):
        path = trace.TracerouteController.PATH_SWITCHES
        code, body = self.client.get(path)

        if code != 200:
            raise RuntimeError('failed to list datapath: %s' % code)

        for entry in body:
            self.dump_datapath(entry)

    @classmethod
    def subcmd_show(cls, subcmd):
        p = subcmd.add_parser('show', help='show specific datapath')
        p.add_argument('dpid', help='datapath id to show')
        return p

    def handle_show(self):
        path = trace.TracerouteController.PATH_SWITCHES_DPID
        path = path.format(dpid=self.args.dpid)
        code, body = self.client.get(path)

        if code != 200:
            raise RuntimeError('failed to show datapath: %s' % code)

        self.dump_datapath(body)

    @classmethod
    def subcmd_dump_flows(cls, subcmd):
        p = subcmd.add_parser('dump-flows', help='show flow entries')
        p.add_argument('dpid', help='datapath id to show flows')
        return p

    def handle_dump_flows(self):
        path = trace.TracerouteController.PATH_SWITCHES_FLOW
        path = path.format(dpid=self.args.dpid)
        code, body = self.client.get(path)

        if code != 200:
            raise RuntimeError('failed to dump flow entries: %s' % code)

        for entry in body:
            self.println(entry)

    @classmethod
    def subcmd_add_flow(cls, subcmd):
        p = subcmd.add_parser('add-flow', help='add flow entry')
        p.add_argument('dpid', help='datapath id to add flow entry')
        p.add_argument('flow', help='flow entry to add')
        return p

    def handle_add_flow(self):
        path = trace.TracerouteController.PATH_SWITCHES_FLOW
        path = path.format(dpid=self.args.dpid)

        # test flow format
        ofpstr.ofp4.str2mod(self.args.flow)

        code, body = self.client.put(path, {'entry': self.args.flow})

        if code != 204:
            raise RuntimeError('failed to add flow entry: %s' % code)

    @classmethod
    def subcmd_del_flows(cls, subcmd):
        p = subcmd.add_parser('del-flows', help='delete flow entries')
        p.add_argument('dpid', help='datapath id to delete flow entries')
        p.add_argument('flow', help='flow entry for specifying match')
        return p

    def handle_del_flows(self):
        path = trace.TracerouteController.PATH_SWITCHES_FLOW
        path = path.format(dpid=self.args.dpid)

        # test flow format
        ofpstr.ofp4.str2mod(self.args.flow)

        code, body = self.client.delete(path, {'entry': self.args.flow})

        if code != 204:
            raise RuntimeError('failed to delete flow entries: %s' % code)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1',
                        help='controller host')
    parser.add_argument('--port', type=int, default=8080,
                        help='controller port')
    try:
        Ofctl.register_subcommand(parser.add_subparsers(dest='subcmd'))
        Ofctl.run(parser.parse_args())
    except Exception as e:
        parser.error('%s: %s' % (type(e).__name__, str(e)))


if __name__ == '__main__':
    main()
