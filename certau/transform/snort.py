from urlparse import urlparse

from .text import StixTextTransform


class StixSnortTransform(StixTextTransform):
    """Generate observable details for Snort.

    This class can be used to generate a list of indicators (observables)
    from a STIX package in a format suitable for importing into the Snort
    network-based intrusion detection system as Snort rules.

    Args:
        package: the STIX package to transform
        separator: the delimiter used in text output
        include_header: a boolean value indicating whether
            or not headers should be included in the output
        header_prefix: a string prepended to each header row
        snort_initial_sid: the initial snort rule number the script should
            start counting from.
        snort_rule_revision: a number indicating which revision of the snort
            rule should be generated. The default is 1 (first version of the
            rule).
        snort_rule_action: a value from the following list that indicates the
            rule action that all generated snort rules will have:
            [alert|log|pass|activate|dynamic|drop|reject|sdrop]
    """

    OBJECT_FIELDS = {
        'Address': ['address_value'],
        'DomainName': ['value'],
        'SocketAddress': ['ip_address.address_value'],
        'URI': ['value'],
    }

    SNORT_ACTIONS = ['alert', 'log', 'pass', 'activate',
                     'dynamic', 'drop', 'reject', 'sdrop']

    def __init__(self, package, default_title=None, default_description=None,
                 default_tlp='AMBER', separator='\t', include_header=False,
                 header_prefix='#', snort_initial_sid=5500000,
                 snort_rule_revision=1, snort_rule_action='alert'):
        super(StixSnortTransform, self).__init__(
            package, default_title, default_description, default_tlp,
            separator, include_header, header_prefix,
        )
        self.sid = snort_initial_sid
        self.snort_rule_revision = snort_rule_revision
        self.snort_rule_action = snort_rule_action

    # ##### Properties

    @property
    def sid(self):
        return self._sid

    @sid.setter
    def sid(self, sid):
        self._sid = int(sid)

    @property
    def snort_rule_revision(self):
        return self._snort_rule_revision

    @snort_rule_revision.setter
    def snort_rule_revision(self, snort_rule_revision):
        self._snort_rule_revision = int(snort_rule_revision)

    @property
    def snort_rule_action(self):
        return self._snort_rule_action

    @snort_rule_action.setter
    def snort_rule_action(self, snort_rule_action):
        if str(snort_rule_action) not in self.SNORT_ACTIONS:
            raise TypeError('invalid Snort action')
        self._snort_rule_action = str(snort_rule_action)

    # ##### Class helper methods

    def snort_rule_text(self, match, conditions):
        rule = '{} '.format(self.snort_rule_action)
        rule += '{} ('.format(match)
        for condition in conditions:
            rule += '{}; '.format(condition)
        rule += 'sid:{}; '.format(self.sid)
        rule += 'rev:{}; '.format(self.snort_rule_revision)
        rule += 'classtype:bad-unknown;)\n'
        return rule

    # ##### Overridden class methods

    def text_for_observable(self, observable, object_type):
        text = ''
        id_ = observable['id']
        if self.OBJECT_FIELDS and object_type in self.OBJECT_FIELDS:
            if object_type == 'Address' or object_type == 'SocketAddress':
                for field in observable['fields']:
                    if object_type == 'Address':
                        address = field['address_value']
                    else:
                        address = field['ip_address.address_value']
                    text += self.snort_rule_text(
                        match='ip any any -> {} any'.format(address),
                        conditions=[
                            'flow:established,to_server',
                            'msg:"CTI-Toolkit connection to potentially '
                            'malicious server {} (ID {})"'.format(address, id_),
                        ],
                    )
            elif object_type == 'DomainName':
                for field in observable['fields']:
                    domain = field['value']
                    text += self.snort_rule_text(
                        match='tcp any any -> $EXTERNAL_NET $HTTP_PORTS',
                        conditions=[
                            'flow:established,to_server',
                            'content:"{}"'.format(domain),
                            'http_header',
                            'nocase',
                            'msg:"CTI-Toolkit connection to potentially '
                            'malicious domain {} (ID {})"'.format(domain, id_),
                        ],
                    )
            elif object_type == 'URI':
                for field in observable['fields']:
                    url = urlparse(field['value'])
                    text += self.snort_rule_text(
                        match='tcp any any -> $EXTERNAL_NET $HTTP_PORTS',
                        conditions=[
                            'flow:established,to_server',
                            'content:"{}"'.format(url.netloc),
                            'http_header',
                            'nocase',
                            'uricontent:"{}"'.format(url.path),
                            'nocase',
                            'msg:"CTI-Toolkit connection to potentially '
                            'malicious url {} (ID {})"'.format(url.geturl(), id_),
                        ],
                    )
            self.sid += 1
        return text
