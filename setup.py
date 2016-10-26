#!/usr/bin/env python

from setuptools import setup

setup(
    name='cti-toolkit',
    version='1.1.0.dev2',
    description='CERT Australia cyber threat intelligence (CTI) toolkit',
    url='https://github.com/certau/cti-toolkit/',
    author='CERT Australia, Australian Government',
    author_email='info@cert.gov.au',
    license='BSD',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='STIX TAXII',
    packages={
        'certau',
        'certau/scripts',
        'certau/source',
        'certau/transform',
    },
    entry_points={
        'console_scripts': [
            'stixtransclient.py=certau.scripts.stixtransclient:main',
        ],
    },
    install_requires=[
        'configargparse',
        'lxml',
        'libtaxii',
        'cybox==2.1.0.12',
        'stix==1.1.1.7',
        'stix-ramrod',
        'mixbox',
        'pymisp',
        'requests',
    ]
)
