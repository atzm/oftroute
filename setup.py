#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


setup(
    name='oftrace',
    version='0.0.1',
    description='OpenFlow traceroute',
    author='Atzm WATANABE',
    author_email='atzm@atzm.org',
    entry_points={'console_scripts': [
        'oft-controller = oftrace.cmd.controller:main',
        'oft-traceroute = oftrace.cmd.traceroute:main',
        'oft-ofctl      = oftrace.cmd.ofctl:main',
    ]},
    packages=find_packages(exclude=['test']),
    install_requires=[
        'ryu>=3.26',
        'ofpstr>=0.1.3',
        'websocket-client>=0.21.0',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 2.7',
    ],
)
