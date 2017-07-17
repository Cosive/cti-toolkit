"""Classes that provide a source of STIX packages.

These classes should implement the ``next_stix_package()`` method.
"""

from .taxii import TaxiiContentBlockSource
from .files import StixFileSource
