import logging
import os

import ramrod
from stix.core import STIXPackage
from stix.utils.parser import UnsupportedVersionError
from stix.extensions.marking import ais  # Needed to support AIS Markings


class StixSource(object):
    """A base class for sources of STIX packages."""

    def __init__(self):
        self._logger = logging.getLogger()
        self._index = 0
        self._source_items = []
        self._file_names = dict()

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

    def save_package(self, package, directory):
        """Save a package to the given directory using its file name."""
        file_name = self.file_name_for_package(package)
        if file_name:
            full_path = os.path.join(directory, file_name)
            # TODO: what if the file already exists ??
            with open(full_path, 'w') as file_:
                file_.write(package.to_xml())

    def io_for_source_item(self, source_item):
        """Return an io type object for the source item."""
        # Default behaviour is to return the source_item itself
        return source_item

    def file_name_for_source_item(self, source_item):
        # Default behaviour is to assume the source item is a file name
        return os.path.basename(source_item)

    def next_stix_package(self):
        """Return the next STIX package available from the source (or None)."""
        package = None
        while self._index < len(self._source_items):
            source_item = self._source_items[self._index]
            self._index += 1

            source_io = self.io_for_source_item(source_item)
            package = self.load_stix_package(source_io)
            file_name = self.file_name_for_source_item(source_item)
            if package is not None:
                self.set_file_name_for_package(package, file_name)
                break
            else:
                self._logger.info("skipping source item '%s' - invalid "
                                  "XML/STIX", file_name)
        return package

    def add_source_item(self, source_item):
        self._source_items.append(source_item)

    def file_name_for_package(self, package):
        """Provide a suggested file name for the given package."""
        return self._file_names.get(package.id_)

    def set_file_name_for_package(self, package, file_name):
        if package is not None:
            self._file_names[package.id_] = file_name
