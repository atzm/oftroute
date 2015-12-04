# -*- coding: utf-8 -*-

import ryu.cfg


ryu.cfg.CONF.register_opts(
    [
        ryu.cfg.IntOpt('cookie', default=(1 << 64) - 2,
                       help='cookie value of flow entry for traceroute'),
        ryu.cfg.StrOpt('metafield', default='metadata',
                       help='metadata field name to identify probe frame'),
        ryu.cfg.IntOpt('metavalue', default=(1 << 64) - 2,
                       help='metadata field value to identify probe frame'),
        ryu.cfg.StrOpt('ruleclass', default='RuleVlanPcp7',
                       help='rule class to handle probe frame'),
    ],
    'oftroute')


def cookie():
    return ryu.cfg.CONF.oftroute.cookie


def metafield():
    return ryu.cfg.CONF.oftroute.metafield


def metavalue():
    return ryu.cfg.CONF.oftroute.metavalue


def ruleclass():
    return ryu.cfg.CONF.oftroute.ruleclass
