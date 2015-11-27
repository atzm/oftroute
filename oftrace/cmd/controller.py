# -*- coding: utf-8 -*-

import sys

import ryu.cmd.manager


def main():
    sys.argv.append('oftrace.config')
    sys.argv.append('oftrace.flow')
    sys.argv.append('oftrace.trace')
    ryu.cmd.manager.main()


if __name__ == '__main__':
    main()
