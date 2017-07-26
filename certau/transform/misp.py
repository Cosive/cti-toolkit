import time
import warnings
from datetime import datetime

from cybox.common import Hash
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI

# suppress PyMISP warning about Python 2
warnings.filterwarnings('ignore', 'You\'re using python 2, it is strongly '
                        'recommended to use python >=3.4')
from pymisp import PyMISP

from certau.lib.stix.helpers import package_time
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

    def __init__(self, package, default_title=None, default_description=None,
                 default_tlp='AMBER',
                 misp=None,        # PyMISP object must be provided
                 distribution=0,   # this organisation only
                 threat_level=1,   # threat
                 analysis=2,       # analysis
                 information=None,
                 published=False):
        super(StixMispTransform, self).__init__(
            package, default_title, default_description, default_tlp,
        )
        self.misp = misp
        self.distribution = distribution
        self.threat_level = threat_level
        self.analysis = analysis
        self.information = information
        self.published = published

    # ##### Properties

    @property
    def misp(self):
        return self._misp

    @misp.setter
    def misp(self, misp):
        if not isinstance(misp, PyMISP):
            raise TypeError('expected PyMISP object')
        self._misp = misp

    @property
    def distribution(self):
        return self._distribution

    @distribution.setter
    def distribution(self, distribution):
        self._distribution = int(distribution)

    @property
    def threat_level(self):
        return self._threat_level

    @threat_level.setter
    def threat_level(self, threat_level):
        self._threat_level = int(threat_level)

    @property
    def analysis(self):
        return self._analysis

    @analysis.setter
    def analysis(self, analysis):
        self._analysis = int(analysis)

    @property
    def information(self):
        return self._information

    @information.setter
    def information(self, information):
        self._information = '' if information is None else str(information)

    @property
    def published(self):
        return self._published

    @published.setter
    def published(self, published):
        self._published = bool(published)

    @property
    def event(self):
        return self._event

    @event.setter
    def event(self, event):
        self._event = event

    # ##### Class helper methods

    @staticmethod
    def get_misp_object(misp_url, misp_key, misp_ssl=False, misp_cert=None):
        """Returns a PyMISP object for communicating with a MISP host.

        Args:
            misp_url: URL for MISP API end-point
            misp_key: API key for accessing MISP API
            misp_ssl: a boolean value indicating whether the server's SSL
                certificate will be verified
            misp_cert: a tuple containing a certificate and key for SSL
                client authentication
        """
        return PyMISP(misp_url, misp_key, ssl=misp_ssl, cert=misp_cert)

    def init_misp_event(self):
        if not self.information:
            # Try the package header for some 'info'
            title = self.package_title()
            description = self.package_description()
            if title or description:
                self.information = title
                if title and description:
                    self.information += ' | '
                if description:
                    self.information += description

        timestamp = package_time(self.package) or datetime.now()

        self.event = self.misp.new_event(
            distribution=self.distribution,
            threat_level_id=self.threat_level,
            analysis=self.analysis,
            info=self.information,
            date=timestamp.strftime('%Y-%m-%d'),
        )

        # Add TLP tag to the event
        package_tlp = self.package_tlp().lower()
        tlp_tag_id = None
        misp_tags = self.misp.get_all_tags()
        if 'Tag' in misp_tags:
            for tag in misp_tags['Tag']:
                if tag['name'] == 'tlp:{}'.format(package_tlp):
                    tlp_tag_id = tag['id']
                    break
        if tlp_tag_id is not None:
            self.misp.tag(self.event['Event']['uuid'], tlp_tag_id)

    # ##### Overridden class methods

    def publish_fields(self, fields, object_type):
        if isinstance(self.MISP_FUNCTION_MAPPING[object_type], list):
            for field, function in zip(
                    self.OBJECT_FIELDS[object_type],
                    self.MISP_FUNCTION_MAPPING[object_type]):
                if field in fields:
                    add_method = getattr(self.misp, function)
                    add_method(self.event, fields[field])
        else:
            add_method = getattr(self.misp,
                                 self.MISP_FUNCTION_MAPPING[object_type])
            if object_type == 'File':
                # Convert the hash type and value to kwargs
                hash_type = fields['hashes.type_'].lower()
                kwargs = {hash_type: fields['hashes.simple_hash_value']}
                add_method(self.event, **kwargs)
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
                    add_method(self.event, regkey, regvalue)
                else:
                    self._logger.debug('skipping WinRegistryKey with no data')
            else:
                # A single value
                field = self.OBJECT_FIELDS[object_type][0]
                if field in fields:
                    add_method(self.event, fields[field])

    def publish_observable(self, observable, object_type):
        if 'fields' in observable:
            for fields in observable['fields']:
                self.publish_fields(fields, object_type)

    def publish(self):
        if self.observables:
            self._logger.info("Publishing results to MISP")
            self.init_misp_event()
            for object_type in sorted(self.OBJECT_FIELDS.keys()):
                if object_type in self.observables:
                    for observable in self.observables[object_type]:
                        self.publish_observable(observable, object_type)
            if self.published:
                self.misp.publish(self.event)
        else:
            self._logger.info("Package has no observables - skipping")
