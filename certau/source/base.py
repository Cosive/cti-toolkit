import ramrod
from stix.core import STIXPackage
from stix.utils.parser import UnsupportedVersionError
from stix.extensions.marking import ais  # Needed to support AIS Markings


class StixSource(object):
    """A base class for sources of STIX packages."""

    def load_stix_package(self, stix_file):
        """Helper for loading and updating (if required) a STIX package."""
        try:
            package = STIXPackage.from_xml(stix_file)
        except UnsupportedVersionError:
            updated = ramrod.update(stix_file, to_='1.1.1')
            document = updated.document.as_stringio()
            try:
                package = STIXPackage.from_xml(document)
            except Exception:
                package = None
        except Exception:
            package = None

        return package

    def next_stix_package(self):
        """Return the next STIX package available from the source (or None)."""
        raise NotImplementedError
