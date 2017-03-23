"""Test setup."""
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
def process_package_args(monkeypatch):
    """Mock the stixtransclient._process_package function, returning the
    args from the last call to it.
    """
    last_call_args = []

    def mock_return(pkg, cls, kwargs):
        """Drop-in replacement for capturing how it was called."""
        del last_call_args[:]
        last_call_args.extend((pkg, cls, kwargs))

    monkeypatch.setattr(stixtransclient, '_process_package', mock_return)

    return last_call_args
