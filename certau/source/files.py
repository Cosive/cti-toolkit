import os

from .base import StixSourceItem


class StixFileSourceItem(StixSourceItem):

    def io(self):
        return self.source_item

    def file_name(self):
        return self.source_item


class StixFileSource(object):
    """Return STIX packages from a file or directory.

    Args:
        files: an array containing the names of one or more files or
            directories
        recurse: an optional boolean value (default False), which when set
            to True, will cause subdirectories to be searched recursively
    """

    def __init__(self, files, recurse=False):
        self.files = files
        self.recurse = recurse

    def source_items(self):
        for file_ in self.files:
           for another_file in self.scan(file_):
               yield StixFileSourceItem(another_file)

    def scan(self, file_):
        if os.path.isdir(file_):
            for dir_file in sorted(os.listdir(file_)):
                path = os.path.join(file_, dir_file)
                if os.path.isdir(path) and self.recurse:
                    self.scan(path)
                elif os.path.isfile(path):
                    yield path
        elif os.path.isfile(file_):
            yield file_
