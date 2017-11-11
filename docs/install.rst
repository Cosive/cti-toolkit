.. _installation:

Installation
============

This document describes how to install the CERT Australia CTI Toolkit.

Installation is streamlined using Python's setuptools. The following
installation process has been tested on clean install of Ubuntu Server 16.04 and CentOS 7.

#. Install prerequisites required by setuptools and libtaxii::

**For Ubuntu/Debian**::

    $ sudo apt-get install python-pip python-dev libxml2-dev libxslt1-dev libz-dev

**For RHEL/CentOS**::

    $ sudo yum install python-pip python-devel python-lxml libxml2-devel zlib-devel

#. Install the cti-toolkit::

    $ sudo pip install cti-toolkit

That's it. You should now be able to run utilities, such as
``stixtransclient.py``::

    $ stixtransclient.py -h


Documentation
-------------

Online documentation is available at `<http://cti-toolkit.readthedocs.org/>`_.

To build the documentation you need Sphinx::

    $ sudo pip install Sphinx sphinxcontrib-napoleon sphinx_rtd_theme
    $ cd docs
    $ make html

This will create an HTML version of the documentation in ``docs/_build/html``.

Tests
-----

Requires tox::

    $ sudo pip install tox

Then run the tests from the repository root using::

    $ tox

Development
-----------

To build a development version from the codebase perform the following steps.

#. Install prerequisites required by setuptools and libtaxii::

**For Ubuntu/Debian**::

    $ sudo apt-get install python-pip python-dev libxml2-dev libxslt1-dev libz-dev

**For RHEL/CentOS**::

    $ sudo yum install python-pip python-devel python-lxml libxml2-devel zlib-devel

#. Clone the github repository::

    $ sudo git clone https://github.com/certau/cti-toolkit.git

#. Create a vurtualenv environment::

    $ cd cti-toolkit
    $ sudo pip install virtualenv
    $ virtualenv env
    $ source env/bin/activate

#. Install all the python develeopment requirements into the virtualenv::

    $ sudo pip install -r requirements-dev.txt

#. Build and Install the local cti-toolkit::

    $ sudo python setup.py install

That's it. You should now be able to run utilities, such as
``stixtransclient.py``::

    $ stixtransclient.py -h


