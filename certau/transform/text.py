from __future__ import absolute_import

import contextlib
import csv
import StringIO

from .base import StixTransform


class StixTextTransform(StixTransform):
    """A transform for converting a STIX package to simple text.

    This class and its subclasses implement the :py:func:`text` class method
    which returns a string representation of the STIX package.
    The entire text output may optionally be preceded by a header string.
    Typically, each line of the output will contain details for a particular
    Cybox observable.
    Output is grouped by observable type.
    Each group of observables (by type) may also contain an additional header
    string.

    Args:
        package: the STIX package to transform
        separator: the delimiter used in text output
        include_header: a boolean value indicating whether
            or not headers should be included in the output
        header_prefix: a string prepended to each header row

    Attributes:
        HEADER_LABELS: a list of field names that are printed by the
            :py:func:`header` function.

        OBJECT_HEADER_LABELS: a dict, keyed by object type, containing
            field names associated with an object type. These are printed
            by the :py:func:`header_for_object_type` function.
    """

    HEADER_LABELS = []
    OBJECT_HEADER_LABELS = {}

    def __init__(self, package, default_title=None, default_description=None,
                 default_tlp='AMBER', separator='|', include_header=True,
                 header_prefix='#'):
        super(StixTextTransform, self).__init__(
            package, default_title, default_description, default_tlp,
        )
        self.separator = separator
        self.include_header = include_header
        self.header_prefix = header_prefix

    # ##### Properties

    @property
    def separator(self):
        return self._separator

    @separator.setter
    def separator(self, separator):
        self._separator = '' if separator is None else str(separator)

    @property
    def include_header(self):
        return self._include_header

    @include_header.setter
    def include_header(self, include_header):
        self._include_header = bool(include_header)

    @property
    def header_prefix(self):
        return self._header_prefix

    @header_prefix.setter
    def header_prefix(self, header_prefix):
        if header_prefix is None:
            self._header_prefix = ''
        else:
            self._header_prefix = str(header_prefix)

    # ##### Class helper methods

    def join(self, items):
        """str.join, but with quoting when the items contain delimiters."""
        with contextlib.closing(StringIO.StringIO()) as sio:
            csv.writer(sio, delimiter=self.separator).writerow(items)
            return sio.getvalue().strip()

    # ##### Overridden class methods

    def header(self):
        """Returns a header string to display with transform."""
        if self.HEADER_LABELS:
            return '{} {}\n'.format(
                self.header_prefix,
                self.join(self.HEADER_LABELS),
            )
        else:
            return ''

    def header_for_object_type(self, object_type):
        """Returns a header string associated with an object type."""
        if object_type in self.OBJECT_HEADER_LABELS:
            return '{} {}\n'.format(
                self.header_prefix,
                self.join(self.OBJECT_HEADER_LABELS[object_type]),
            )
        else:
            return ''

    def text_for_fields(self, fields, object_type):
        """Returns a string representing the given object fields."""
        field_values = []
        if self.OBJECT_FIELDS and object_type in self.OBJECT_FIELDS:
            for field in self.OBJECT_FIELDS[object_type]:
                field_value = fields[field] if field in fields else 'None'
                field_values.append(field_value)
        return self.join(field_values)

    def text_for_observable(self, observable, object_type):
        """Returns a string representing the given observable."""
        text = ''
        for field in observable['fields']:
            text += self.text_for_fields(field, object_type) + '\n'
        return text

    def text_for_object_type(self, object_type):
        """Returns a string representing observables of the given type."""
        text = ''
        if object_type in self.observables:
            for observable in self.observables[object_type]:
                text += self.text_for_observable(observable, object_type)
        return text

    def text(self):
        """Returns a string representation of the STIX package."""
        text = self.header() if self.include_header else ''

        if self.OBJECT_FIELDS:
            object_types = self.OBJECT_FIELDS.keys()
        else:
            object_types = self.observables.keys()
        for object_type in sorted(object_types):
            object_text = self.text_for_object_type(object_type)
            if object_text:
                if self.include_header:
                    text += self.header_for_object_type(object_type)
                text += object_text
        return text
