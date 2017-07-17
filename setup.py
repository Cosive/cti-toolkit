#!/usr/bin/env python

from setuptools import setup

from certau import package_name, package_version

setup(
    name=package_name,
    version=package_version,
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
        'certau/lib',
        'certau/lib/stix',
        'certau/lib/taxii',
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
        'cybox==2.1.0.13',
        'stix==1.1.1.8',
        'stix-ramrod',
        'mixbox',
        'pymisp>=2.4.71',
        'requests',
    ]
)
