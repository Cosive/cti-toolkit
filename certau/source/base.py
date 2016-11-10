import ramrod
from stix.core import STIXPackage
from stix.utils.parser import UnsupportedVersionError


class StixSource(object):
    """A base class for sources of STIX packages."""

    def load_stix_package(self, stix_file, stix_version='1.2'):
        """Helper for loading and updating (if required) a STIX package."""
        try:
            # This will attempt to ingest the STIX package
            # if its not at a version supported by the version of python-stix, then we try to upgrade it
            package = STIXPackage.from_xml(stix_file)
            
        except UnsupportedVersionError as e:
            print "Found STIX Version {0}. Converting to {0}: {}".format(e.found, e.expected, e.message)
            try:
                updated = ramrod.update(stix_file, to_=stix_version)
                document = updated.document.as_stringio()
                package = STIXPackage.from_xml(document)
            except UnsupportedVersionError as e:
                print "ERROR - STIX Version {0} is unsupported: {}".format(e.found, e.message)
                package = None
            except Exception as e:
                print "ERROR - Exception occurred: {}".format(e.message)
                package = None
        except UnknownVersionError:
            print "ERROR - No STIX Version found in the source document."
            package = None
        except Exception as e:
            print "ERROR - Exception occurred: {}".format(e.message)
            package = None

        return package

    def next_stix_package(self):
        """Return the next STIX package available from the source (or None)."""
        raise NotImplementedError
