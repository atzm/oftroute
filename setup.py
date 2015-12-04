#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup, find_packages

longdesc = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

setup(
    name='oftroute',
    version='0.0.1',
    description='OpenFlow traceroute',
    long_description=longdesc,
    author='Atzm WATANABE',
    author_email='atzm@atzm.org',
    url='https://github.com/atzm/oftroute',
    license='Apache-2.0',
    entry_points={'console_scripts': [
        'oft-controller = oftroute.cmd.controller:main',
        'oft-traceroute = oftroute.cmd.traceroute:main',
        'oft-ofctl      = oftroute.cmd.ofctl:main',
    ]},
    packages=find_packages(exclude=['test']),
    install_requires=[
        'ryu>=3.26',
        'ofpstr>=0.1.3',
        'websocket-client>=0.21.0',
    ],
    keywords=['network', 'ryu', 'openflow', 'traceroute'],
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Networking',
    ],
)
