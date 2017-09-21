"""Test setup."""

from __future__ import absolute_import, division, print_function, unicode_literals
from future.standard_library import install_aliases
install_aliases()

import sys
import io
import pytest
import stix
from certau.scripts import stixtransclient


@pytest.fixture(scope='session')
def package_111():
    """Create a 'package_111' fixture.

    If you include 'package_111' as a test argument, you have access to a
    pre-loaded STIX package, ready to transform.
    """
    with open('TEST-STIX-1.1.1.xml', encoding='utf-8') as stix_f:
        stix_io = io.StringIO(stix_f.read())
        return stix.core.STIXPackage.from_xml(stix_io)

@pytest.fixture(scope='session')
def package_12():
    """Create a 'package_12' fixture.

    If you include 'package_12' as a test argument, you have access to a
    pre-loaded STIX package, ready to transform.
    """
    with open('TEST-STIX-1.2.xml', encoding='utf-8') as stix_f:
        stix_io = io.StringIO(stix_f.read())
        return stix.core.STIXPackage.from_xml(stix_io)


@pytest.fixture
def client_wrapper(monkeypatch):
    """Wrapper around the client to test command line arguments are mapped to
    stixtransclient._process_package() properly.
    """
    last_call_args = []

    def save_args(pkg, cls, kwargs):
        """Drop-in replacement for capturing how it was called."""
        del last_call_args[:]
        last_call_args.extend((pkg, cls, kwargs))
    monkeypatch.setattr(stixtransclient, '_process_package', save_args)

    class ClientWrapper(object):
        """Wrap the two different helpers."""
        @staticmethod
        def set_command_line(new_args):
            """Set sys.argv."""
            filename = sys.argv[0]
            full_args = [filename] + new_args
            monkeypatch.setattr(sys, 'argv', full_args)

        @staticmethod
        def last_args():
            """Return the last args passed to
            stixtransclient._process_package().
            """
            return last_call_args

    return ClientWrapper
