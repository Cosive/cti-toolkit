#!/usr/bin/env python

import os
from setuptools import setup

from certau import package_name, package_version

def here(*path):
    return os.path.join(os.path.dirname(__file__), *path)


def get_file_contents(filename):
    with open(here(filename)) as fp:
        return fp.read()


# This is a quick and dirty way to include everything from
# requirements.txt as package dependencies.
install_requires_list = get_file_contents('requirements.txt').split()

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
        'certau/util',
        'certau/util/stix',
        'certau/util/taxii',
        'certau/scripts',
        'certau/source',
        'certau/transform',
    },
    entry_points={
        'console_scripts': [
            'stixtransclient.py=certau.scripts.stixtransclient:main',
        ],
    },

    install_requires=install_requires_list
)
