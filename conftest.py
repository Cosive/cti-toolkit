"""Test setup."""
import sys
import StringIO
import pytest
import stix
import stixtransclient


@pytest.fixture(scope='module')
def package():
    """Create a 'package' fixture.

    If you include 'package' as a test argument, you have access to a
    pre-loaded STIX package, ready to transform.
    """
    with open('tests/CA-TEST-STIX.xml', 'rb') as stix_f:
        stix_io = StringIO.StringIO(stix_f.read())
        return stix.core.STIXPackage.from_xml(stix_io)


@pytest.fixture
def stixtransclient_commandline(monkeypatch):
    """Allow setting sys.argv."""
    class Args(object):
        """Just a helper type to allow for returning something with a 'set'
        method.
        """
        @staticmethod
        def set(new_args):
            """Set sys.argv."""
            filename = sys.argv[0]
            full_args = [filename] + new_args
            monkeypatch.setattr(sys, 'argv', full_args)

    return Args


@pytest.fixture
def process_package(monkeypatch):
    """Mock the stixtransclient._process_package function, returning the
    args from the last call to it.
    """
    last_call_args = []

    def mock_return(pkg, cls, kwargs):
        """Drop-in replacement for capturing how it was called."""
        del last_call_args[:]
        last_call_args.extend((pkg, cls, kwargs))

    monkeypatch.setattr(stixtransclient, '_process_package', mock_return)

    class Args(object):
        """Helper to allow for retrieving the last args."""
        @staticmethod
        def was_called_with():
            """Return the current args."""
            return last_call_args

    return Args
