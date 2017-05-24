import os

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
        super(StixFileSource, self).__init__()
        for file_ in files:
            self.add_file(file_, recurse)

    def add_file(self, file_, recurse):
        if os.path.isdir(file_):
            for dir_file in sorted(os.listdir(file_)):
                path = os.path.join(file_, dir_file)
                if os.path.isdir(path) and recurse:
                    self.add_file(path, recurse)
                elif os.path.isfile(path):
                    self.add_source_item(path)
        elif os.path.isfile(file_):
            self.add_source_item(file_)
