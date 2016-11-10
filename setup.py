#!/usr/bin/env python

from setuptools import setup

<<<<<<< HEAD
setup(
    name='cti-toolkit',
    version='1.1.0.dev2',
    description='CERT Australia cyber threat intelligence (CTI) toolkit',
    url='https://github.com/certau/cti-toolkit/',
=======
setup(name='certau_stix_toolkit',
    version='1.0.1',
    description='CERT Australia STIX utilities',
>>>>>>> refs/remotes/origin/stix-1.2
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
<<<<<<< HEAD
        'cybox==2.1.0.12',
        'stix==1.1.1.7',
        'stix-ramrod',
=======
        'cybox==2.1.0.13',
        'stix==1.2.0.2',
        'stix-ramrod==1.1.0',
>>>>>>> refs/remotes/origin/stix-1.2
        'mixbox',
        'pymisp',
        'requests',
    ]
)
