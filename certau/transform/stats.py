from .text import StixTextTransform


class StixStatsTransform(StixTextTransform):
    """Generate summary statistics for a STIX package.

    Prints a count of the number of observables for each object type
    contained in the package.

    Args:
        package: the STIX package to process
        separator: a string separator used in the text output
        include_header: a boolean value that indicates whether or not header
            information should be included in the text output
        header_prefix: a string prepended to header lines in the output
        pretty_text: a boolean that indicates whether or not the text
            should be made pretty by aligning the columns in
            the text output
    """

    LINE = '++++++++++++++++++++++++++++++++++++++++'

    def __init__(self, package, separator='\t', include_header=True,
                 header_prefix='', pretty_text=True):
        super(StixStatsTransform, self).__init__(
            package, separator, include_header, header_prefix,
        )
        self._pretty_text = pretty_text

    def header(self):
        header = self._header_prefix + self.LINE + '\n'
        header += self._header_prefix + 'Summary statistics:'

        title = self.package_title()
        if title:
            header += ' ' + title

        tlp = self.package_tlp()
        if tlp:
            header += ' (' + tlp + ')'

        header += '\n' + self._header_prefix + self.LINE + '\n'
        return header

    def text_for_object_type(self, object_type):
        if object_type in self._observables:
            count = len(self._observables[object_type])
        else:
            count = 0
        if self._pretty_text:
            text = '{0:<35} {1:>4}\n'.format(
                object_type + ' observables:',
                count,
            )
        else:
            text = self.join([object_type, count]) + '\n'
        return text
