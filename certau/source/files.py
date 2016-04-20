import os
import logging

from .base import StixSource


class StixFileSource(StixSource):
    """Return STIX packages from a file or directory.

    Args:
        files: an array containing the names of one or more files or
            directories
        recurse: an optional boolean value (default False), which when set
            to True, will cause subdirectories to be searched recursively
    """

    def __init__(self, files, recurse=False):
        self._logger = logging.getLogger()
        self._files = []
        for file_ in files:
            self._add_file(file_, recurse)
        self._index = 0

    def _add_file(self, file_, recurse):
        if os.path.isdir(file_):
            for dir_file in sorted(os.listdir(file_)):
                path = os.path.join(file_, dir_file)
                if os.path.isdir(path) and recurse:
                    self._add_file(path, recurse)
                elif os.path.isfile(path):
                    self._files.append(path)
        elif os.path.isfile(file_):
            self._files.append(file_)

    def next_stix_package(self):
        package = None
        while self._index < len(self._files):
            file_ = self._files[self._index]
            self._index += 1
            package = self.load_stix_package(file_)
            if package:
                break
            else:
                self._logger.info(
                    "skipping file '{}' - invalid XML/STIX".format(file_)
                )

        return package
