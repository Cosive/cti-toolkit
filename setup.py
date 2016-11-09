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
        'lxml',
        'libtaxii',
        'cybox==2.1.0.13',
        'stix==1.2.0.2',
        'stix-ramrod==1.1.0',
        'mixbox',
        'pymisp',
        'requests',
    ]
)
