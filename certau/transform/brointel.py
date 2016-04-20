import re

from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI

from .text import StixTextTransform


class StixBroIntelTransform(StixTextTransform):
    """Generate observable details for the Bro Intelligence Framework.

    This class can be used to generate a list of indicators (observables)
    from a STIX package in a format suitable for importing into the Bro
    network-based intrusion detection system using its Intelligence
    Framework (see https://www.bro.org/sphinx-git/frameworks/intel.html).

    Args:
        package: the STIX package to process
        separator: a string separator used in the text output
        include_header: a boolean value that indicates whether or not header
            information should be included in the text output
        header_prefix: a string prepended to header lines in the output
        source: a value to include in the output metadata field 'meta.source'
        url: a value to include in the output field metadata 'meta.url'
        do_notice: a value to include in the output metadata field
            'meta.do_notice', if set to 'T' a Bro notice will be raised by Bro
            on a match of this indicator
    """

    OBJECT_FIELDS = {
        'Address': ['address_value'],
        'DomainName': ['value'],
        'EmailMessage': [
            'header.from_.address_value',
            'header.to.address_value',
        ],
        'File': ['hashes.simple_hash_value'],
        'HTTPSession': ['http_request_response.http_client_request.' +
                        'http_request_header.parsed_header.user_agent'],
        'SocketAddress': ['ip_address.address_value'],
        'URI': ['value'],
    }

    OBJECT_CONSTRAINTS = {
        'Address': {
            'category': [Address.CAT_IPV4, Address.CAT_IPV6],
        },
        'URI': {
            'type_': [URI.TYPE_URL],
        },
    }

    STRING_CONDITION_CONSTRAINT = ['None', 'Equals']

    HEADER_LABELS = [
        'indicator', 'indicator_type', 'meta.source', 'meta.url',
        'meta.do_notice', 'meta.if_in', 'meta.whitelist',
    ]

    # Map Cybox object type to Bro Intel types.
    BIF_TYPE_MAPPING = {
        'Address': 'Intel::ADDR',
        'DomainName': 'Intel::DOMAIN',
        'EmailMessage': 'Intel::EMAIL',
        'File': 'Intel::FILE_HASH',
        'HTTPSession': 'Intel::SOFTWARE',
        'SocketAddress': 'Intel::ADDR',
        'URI': 'Intel::URL',
    }

    # Map observable id prefix to source and url.
    BIF_SOURCE_MAPPING = {
        'cert_au': {
            'source': 'CERT-AU',
            'url': 'https://www.cert.gov.au/',
        },
        'CCIRC-CCRIC': {
            'source': 'CCIRC',
            'url': ('https://www.publicsafety.gc.ca/' +
                    'cnt/ntnl-scrt/cbr-scrt/ccirc-ccric-eng.aspx'),
        },
        'NCCIC': {
            'source': 'NCCIC',
            'url': 'https://www.us-cert.gov/',
        },
    }

    def __init__(self, package, separator='\t',
                 include_header=False, header_prefix='#',
                 source='UNKNOWN', url='', do_notice='T'):
        super(StixBroIntelTransform, self).__init__(
            package, separator, include_header, header_prefix,
        )
        self._source = source
        self._url = url
        self._do_notice = do_notice
        # Make URIs suitable for the Bro format (remove protocol)
        self._fix_uris()

    def _fix_uris(self):
        if 'URI' in self._observables:
            for observable in self._observables['URI']:
                if 'fields' in observable:
                    for field in observable['fields']:
                        if 'value' in field:
                            field['value'] = re.sub(
                                pattern=r'^(https?|ftp)://',
                                repl='',
                                string=field['value'],
                            )

    def text_for_object_type(self, object_type):
        text = ''
        if object_type in self._observables:
            for observable in self._observables[object_type]:
                # Look up source and url from observable ID
                id_prefix = observable['id'].split(':')[0]
                if id_prefix in self.BIF_SOURCE_MAPPING:
                    source = self.BIF_SOURCE_MAPPING[id_prefix]['source']
                    url = self.BIF_SOURCE_MAPPING[id_prefix]['url']
                else:
                    source = self._source
                    url = self._url

                bif_type = self.BIF_TYPE_MAPPING[object_type]
                for fields in observable['fields']:
                    for field in self.OBJECT_FIELDS[object_type]:
                        if field in fields:
                            field_values = [
                                fields[field],
                                bif_type,
                                source,
                                url,
                                self._do_notice,
                                '-',
                                '-',
                            ]
                            text += self.join(field_values) + '\n'
        return text
