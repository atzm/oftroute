# -*- coding: utf-8 -*-

import sys

import ryu.cmd.manager


def main():
    sys.argv.append('oftroute.config')
    sys.argv.append('oftroute.flow')
    sys.argv.append('oftroute.trace')
    ryu.cmd.manager.main()


if __name__ == '__main__':
    main()
