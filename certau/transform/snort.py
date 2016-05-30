import re

from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
import pprint

from .text import StixTextTransform


class StixSnortTransform(StixTextTransform):
    """Generate observable details for Snort.

    This class can be used to generate a list of indicators (observables)
    from a STIX package in a format suitable for importing into the Snort
    network-based intrusion detection system as Snort rules.

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

    RULE_CONTENT = 'alert ip any any -> <BADIP> any (flow:established,to_server; msg:"CTI-TOOLKIT Connection to potentially malicious server <BADIP>", sid:<SNORTID>; rev:1; classtype:bad-unknown;)'

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

    def __init__(self, package, separator='\t', include_header=False,
                 include_observable_id=True,
                 snort_initial_sid=5500000, snort_rule_revision=1, snort_rule_action="alert"):
        super(StixSnortTransform, self).__init__(
            package, separator, include_header, include_observable_id,
        )
        self._sid = int(snort_initial_sid)
        self._snort_rule_revision = int(snort_rule_revision)
        self._snort_rule_action = snort_rule_action

    def text_for_object_type(self, object_type):
        text = ''
        if object_type in self._observables:
            for observable in self._observables[object_type]:
                id_ = observable['id']
                for field in observable['fields']:
                    try:
                        ip = field["address_value"]
                        text += '{} ip any any -> {} any (flow:established,to_server; msg:"CTI-TOOLKIT Connection to potentially malicious server {} (ID {})", sid:{}; rev:{}; classtype:bad-unknown;)\n'.format(self._snort_rule_action, ip, ip, id_, self._sid, self._snort_rule_revision)
                    except KeyError:
                        pass
                    else:
                        self._sid += 1
        return text