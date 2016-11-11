import ramrod
from stix.core import STIXPackage
from stix.utils.parser import UnsupportedVersionError


class StixSource(object):
    """A base class for sources of STIX packages."""

    def load_stix_package(self, stix_file, stix_version='1.2'):
        """Helper for loading and updating (if required) a STIX package."""
        try:
            # TODO add in a version check to make sure that the returned STIX is
            # what the user requested. If not, it needs ramrodding
            package = STIXPackage.from_xml(stix_file)
            
        except UnsupportedVersionError:
            updated = ramrod.update(stix_file, to_=stix_version)
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
