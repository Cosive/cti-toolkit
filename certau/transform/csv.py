from .text import StixTextTransform


class StixCsvTransform(StixTextTransform):
    """Generate a CSV formatted summary of observables from a STIX package.

    This class can be used to generate a delimited text dump of the
    observable fields contained in a STIX package. Output is grouped by
    the object type contained in the observable.

    Args:
        package: the STIX package to process
        separator: a string separator used in the text output
        include_header: a boolean value that indicates whether or not header
            information should be included in the text output
        header_prefix: a string prepended to header lines in the output
        include_observable_id: a boolean value indicating whether or not
            the output should include the observable's UUID
        include_condition: a boolean value indicating whether or not the
            output should include additional fields containing the Cybox
            string matching condition (which may be empty)
    """

    OBJECT_FIELDS = {
        'Address': ['category', 'address_value'],
        'DomainName': ['value'],
        'EmailMessage': [
            'header.from_.address_value',
            'header.to.address_value',
            'header.subject',
            'attachments.object_reference',
        ],
        'File': ['file_name', 'hashes.type_', 'hashes.simple_hash_value'],
        'HTTPSession': ['http_request_response.http_client_request.' +
                        'http_request_header.parsed_header.user_agent'],
        'Mutex': ['name'],
        'SocketAddress': [
            'ip_address.category',
            'ip_address.address_value',
            'port.port_value',
            'port.layer4_protocol',
        ],
        'URI': ['value'],
        'WinRegistryKey': ['hive', 'key', 'values.name', 'values.data'],
    }

    OBJECT_HEADER_LABELS = {
        'Address': ['category', 'address'],
        'DomainName': ['domain'],
        'EmailMessage': ['fromaddr', 'toaddr', 'subject', 'attachment_ref'],
        'File': ['file_name', 'hash_type', 'hashes'],
        'HTTPSession': ['user_agent'],
        'Mutex': ['mutex'],
        'SocketAddress': [
            'category',
            'address',
            'port_value',
            'port_protocol',
        ],
        'URI': ['uri'],
        'WinRegistryKey': ['hive', 'key', 'name', 'data'],
    }

    STRING_CONDITION_FIELDS = {
        'DomainName': ['value'],
        'EmailMessage': [
            'header.from_.address_value',
            'header.to.address_value',
            'header.subject',
        ],
        'File': ['file_name'],
        'HTTPSession': ['http_request_response.http_client_request.' +
                        'http_request_header.parsed_header.user_agent'],
        'Mutex': ['name'],
        'URI': ['value'],
        'WinRegistryKey': ['hive', 'key', 'values.name', 'values.data'],
    }

    def __init__(self, package, default_title=None, default_description=None,
                 default_tlp='AMBER', separator='|', include_header=True,
                 header_prefix='#', include_observable_id=True,
                 include_condition=True):
        super(StixCsvTransform, self).__init__(
            package, default_title, default_description, default_tlp,
            separator, include_header, header_prefix,
        )
        self.include_observable_id = include_observable_id
        self.include_condition = include_condition

    # #### Properties

    @property
    def include_observable_id(self):
        return self._include_observable_id

    @include_observable_id.setter
    def include_observable_id(self, include_observable_id):
        self._include_observable_id = bool(include_observable_id)

    @property
    def include_condition(self):
        return self._include_condition

    @include_condition.setter
    def include_condition(self, include_condition):
        self._include_condition = bool(include_condition)

    # #### Class helper methods

    def include_condition_with_property(self, object_type, property_):
        if (self.include_condition and
                object_type in self.STRING_CONDITION_FIELDS and
                property_ in self.STRING_CONDITION_FIELDS[object_type]):
            return True
        else:
            return False

    # ##### Overridden class methods

    def header(self):
        title = self.package_title()
        tlp = self.package_tlp()

        if title or tlp:
            header = self.header_prefix
            if title:
                header += ' {}'.format(title)
            if tlp:
                header += ' (TLP:{})'.format(tlp)
            header += '\n\n'
        else:
            header = ''
        return header

    def header_for_object_type(self, object_type):
        header_values = ['id'] if self.include_observable_id else []
        header_values.extend(self.OBJECT_HEADER_LABELS[object_type])
        if self.include_condition:
            index = 1
            for field in self.OBJECT_FIELDS[object_type]:
                if self.include_condition_with_property(object_type, field):
                    condition_label = header_values[index] + '_condition'
                    header_values.insert(index+1, condition_label)
                    index += 1
                index += 1
        header = '{} {} observables\n'.format(self.header_prefix, object_type)
        header += '{} {}\n'.format(self.header_prefix,
                                   self.join(header_values))
        return header

    def text_for_fields(self, fields, object_type):
        field_values = []
        if self.OBJECT_FIELDS and object_type in self.OBJECT_FIELDS:
            for field in self.OBJECT_FIELDS[object_type]:
                field_value = fields.get(field, 'None')
                field_values.append(field_value)
                if self.include_condition_with_property(object_type, field):
                    c_field = self._condition_key_for_field(field)
                    condition = fields.get(c_field, 'None')
                    field_values.append(condition)
        return self.join(field_values)

    def text_for_object_type(self, object_type):
        text = ''
        if object_type in self.observables:
            for observable in self.observables[object_type]:
                id_ = observable['id']
                for field in observable['fields']:
                    if self.include_observable_id:
                        text += '{}{}'.format(id_, self.separator)
                    text += self.text_for_fields(field, object_type) + '\n'
        if text:
            text += '\n'
        return text
