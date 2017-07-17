import logging
import os

import ramrod
from stix.core import STIXPackage
from stix.utils.parser import UnsupportedVersionError
from stix.extensions.marking import ais  # Needed to support AIS Markings


class StixSourceItem(object):
    """A base class for STIX package containers."""

    def __init__(self, source_item):
        self.source_item = source_item
        try:
            self.stix_package = STIXPackage.from_xml(self.io())
        except UnsupportedVersionError:
            updated = ramrod.update(self.io(), to_='1.1.1')
            document = updated.document.as_stringio()
            self.stix_package = STIXPackage.from_xml(document)
        except Exception:
            logging.error('error parsing STIX package (%s)', self.file_name())
            self.stix_package = None

    def io(self):
        raise NotImplementedError

    def file_name(self):
        raise NotImplementedError

    def save(self, directory):
        try:
            stix_package = self.stix_package
            file_name = self.file_name()
            full_path = os.path.join(directory, file_name)
            logging.info('saving STIX package to file \'%s\'', full_path)
            with open(full_path, 'wb') as file_:
                file_.write(self.stix_package.to_xml())
        except Exception:
            logging.error('unable to save STIX package to file \'%s\'',
                          full_path)
