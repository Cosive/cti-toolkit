#!/usr/bin/env python

from setuptools import setup

setup(name='certau_stix_toolkit',
    version='1.0.1',
    description='CERT Australia STIX utilities',
    author='CERT Australia, Australian Government',
    author_email='info@cert.gov.au',
    url='http://www.cert.gov.au/',
    packages={
        'certau',
        'certau/source',
        'certau/transform',
    },
    scripts=[
        'scripts/stixtransclient.py',
    ],
    install_requires=[
        'configargparse',
        'lxml>=3.7,<4.0',
        'libtaxii>1.1,<2.0',
        'cybox>=2.1.0.13,<3.0',
        'stix>=1.2,<2.0',
        'stix-ramrod>=1.1.0,<2.0',
        'mixbox>=1.0.1,<2.0',
        'pymisp>=2.4,<3.0',
        'requests',
    ]
)
