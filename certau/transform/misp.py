import time
from datetime import datetime

from cybox.common import Hash
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from pymisp import PyMISP

from .base import StixTransform


class StixMispTransform(StixTransform):
    """Insert data from a STIX package into a MISP event.

    This class inserts data from a STIX package into MISP (the Malware
    Information Sharing Platform - see http://www.misp-project.org/).
    A PyMISP (https://github.com/CIRCL/PyMISP) object is passed to
    the constructor and used for communicating with the MISP host.
    The helper function :py:func:`get_misp_object` can be used to
    instantiate a PyMISP object.

    Args:
        package: the STIX package to process
        misp: the PyMISP object used to communicate with the MISP host
        distribution: the distribution setting for the MIST event (0-3)
        threat_level: the threat level setting for the MISP event (0-3)
        analysis: the analysis level setting for the MISP event (0-2)
        information: info field value (string) for the MISP event
        published: a boolean indicating whether the event has been
            published
    """

    OBJECT_FIELDS = {
        'Address': ['address_value'],
        'DomainName': ['value'],
        'EmailMessage': [
            'header.from_.address_value',
            'header.subject',
        ],
        'File': ['hashes.type_', 'hashes.simple_hash_value'],
        'HTTPSession': ['http_request_response.http_client_request.' +
                        'http_request_header.parsed_header.user_agent'],
        'Mutex': ['name'],
        'SocketAddress': ['ip_address.address_value'],
        'URI': ['value'],
        'WinRegistryKey': ['hive', 'key', 'values.name', 'values.data'],
    }

    OBJECT_CONSTRAINTS = {
        'Address': {
            'category': [Address.CAT_IPV4, Address.CAT_IPV6],
        },
        'File': {
            'hashes.type_': [Hash.TYPE_MD5, Hash.TYPE_SHA1, Hash.TYPE_SHA256],
        },
        'URI': {
            'type_': [URI.TYPE_URL],
        },
    }

    STRING_CONDITION_CONSTRAINT = ['None', 'Equals']

    MISP_FUNCTION_MAPPING = {
        'Address': 'add_ipdst',
        'DomainName': 'add_domain',
        'EmailMessage': ['add_email_src', 'add_email_subject'],
        'File': 'add_hashes',
        'HTTPSession': 'add_useragent',
        'Mutex': 'add_mutex',
        'SocketAddress': 'add_ipdst',  # Consider update to PyMISP API for port
        'URI': 'add_url',
        'WinRegistryKey': 'add_regkey',
    }

    def __init__(self, package, misp,
                 distribution=0,   # this organisation only
                 threat_level=1,   # threat
                 analysis=2,       # analysis
                 information=None,
                 published=False):
        super(StixMispTransform, self).__init__(package)
        self._misp = misp
        self._misp_distribution = distribution
        self._misp_threat_level = threat_level
        self._misp_analysis = analysis
        self._misp_information = information
        self._misp_published = published

    @staticmethod
    def get_misp_object(misp_url, misp_key, use_ssl=False):
        """Returns a PyMISP object for communicating with a MISP host.

        Args:
            misp_url: URL for MISP API end-point
            misp_key: API key for accessing MISP API
            use_ssl: a boolean value indicating whether or not the connection
                should use HTTPS (instead of HTTP)
        """
        return PyMISP(misp_url, misp_key, use_ssl)

    def init_misp_event(self):
        if not self._misp_information:
            # Try the package header for some 'info'
            title = self.package_title(default=self._package.id_)
            description = self.package_description()
            if title or description:
                self._misp_information = title
                if title and description:
                    self._misp_information += ' | '
                if description:
                    self._misp_information += description

        if self._package.timestamp:
            timestamp = self._package.timestamp
        else:
            timestamp = datetime.now()

        self._event = self._misp.new_event(
            distribution=self._misp_distribution,
            threat_level_id=self._misp_threat_level,
            analysis=self._misp_analysis,
            info=self._misp_information,
            date=timestamp.strftime('%Y-%m-%d'),
            published=self._misp_published,
        )

        # Add TLP tag to the event - assumes MISP tag ids as follows
        # TLP:RED:   1
        # TLP:AMBER: 2
        # TLP:GREEN: 3
        # TLP:WHITE: 4

        tlp_tags = {'red': 1, 'amber': 2, 'green': 3, 'white': 4}
        tlp_tag_id = tlp_tags[self.package_tlp().lower()]
        self._misp.add_tag(self._event, tlp_tag_id)

    def publish_fields(self, fields, object_type):
        if isinstance(self.MISP_FUNCTION_MAPPING[object_type], list):
            for field, function in zip(
                    self.OBJECT_FIELDS[object_type],
                    self.MISP_FUNCTION_MAPPING[object_type]):
                if field in fields:
                    add_method = getattr(self._misp, function)
                    add_method(self._event, fields[field])
                    time.sleep(0.5)
        else:
            add_method = getattr(self._misp,
                                 self.MISP_FUNCTION_MAPPING[object_type])
            if object_type == 'File':
                # Convert the hash type and value to kwargs
                hash_type = fields['hashes.type_'].lower()
                kwargs = {hash_type: fields['hashes.simple_hash_value']}
                add_method(self._event, **kwargs)
            elif object_type == 'WinRegistryKey':
                # Combine hive and key into regkey
                regkey = ''
                regkey += fields.get('hive', '')
                regkey += fields.get('key', '')
                # Merge the name and values
                regvalue = ''
                regvalue += fields.get('values.name', '')
                data = fields.get('values.data', '')
                if data:
                    regvalue += '\\' if regvalue else ''
                    regvalue += data
                if regkey or regvalue:
                    add_method(self._event, regkey, regvalue)
                else:
                    self._logger.debug('skipping WinRegistryKey with no data')
            else:
                # A single value
                field = self.OBJECT_FIELDS[object_type][0]
                if field in fields:
                    add_method(self._event, fields[field])
            time.sleep(0.5)

    def publish_observable(self, observable, object_type):
        if 'fields' in observable:
            for fields in observable['fields']:
                self.publish_fields(fields, object_type)

    def publish(self):
        if self._observables:
            self._logger.info("Publishing results to MISP")
            self.init_misp_event()
            time.sleep(0.5)
            for object_type in sorted(self.OBJECT_FIELDS.keys()):
                if object_type in self._observables:
                    for observable in self._observables[object_type]:
                        self.publish_observable(observable, object_type)
        else:
            self._logger.info("Package has no observables - skipping")
