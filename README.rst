CERT Australia CTI Toolkit
==========================

This package contains cyber threat intelligence (CTI) tools created
by CERT Australia.

Installation
------------

Installation is streamlined using Python's setuptools. The following installation
process has been tested on clean install of Ubuntu 14.04.

#. Install prerequisites required by setuptools and libtaxii::

    $ sudo apt-get install python-pip python-dev libxml2-dev libxslt1-dev libz-dev

#. Clone the cti-toolkit repository (prompts for github username and password)::

    $ git clone https://github.com/certau/cti-toolkit.git

#. Run the setup.py script to build and install the tools (and pip
   dependencies)::

    $ cd cti-toolkit
    $ sudo python setup.py install

That's it. You should now be able to run utilities, such as stixtransclient.py::

    $ stixtransclient.py -h

Documentation
-------------

A PDF version of the documentation is contained in docs/ctitoolkit.pdf.

To build the documentation you need Sphinx::

    $ sudo pip install Sphinx sphinxcontrib-napoleon
    $ cd docs
    $ make html

This will create an HTML version of the documentation in docs/_build/html.

Tests
-----

Requires tox::

    $ sudo pip install tox

Then run the tests from the repository root using::

    $ tox
