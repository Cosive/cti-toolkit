import re

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
        'Address': ['category', 'address_value'],
        'DomainName': ['value'],
        'URI': ['value'],
    }

    def __init__(self, package, separator='\t', include_header=False,
                 header_prefix='#', snort_initial_sid=5500000,
                 snort_rule_revision=1, snort_rule_action='alert'):
        super(StixSnortTransform, self).__init__(
            package, separator, include_header, header_prefix
        )
        self._sid = int(snort_initial_sid)
        self._snort_rule_revision = int(snort_rule_revision)
        self._snort_rule_action = snort_rule_action

    def text_for_observable(self, observable, object_type):
        text = ''
        id_ = observable['id']
        if self.OBJECT_FIELDS and object_type in self.OBJECT_FIELDS:
            if object_type == 'Address':
                for field in observable['fields']:
                    ip = field['address_value']
                    text += '{} ip any any -> {} any (flow:established,to_server; msg:"CTI-Toolkit connection to potentially malicious server {} (ID {})"; sid:{}; rev:{}; classtype:bad-unknown;)\n'.format(self._snort_rule_action, ip, ip, id_, self._sid, self._snort_rule_revision)
            elif object_type == 'DomainName':
                for field in observable['fields']:
                    domain = field['value']
                    text += '{} tcp any any -> $EXTERNAL_NET $HTTP_PORTS (flow:established,to_server; content:"{}"; http_header; nocase; msg:"CTI-Toolkit connection to potentially malicious domain {} (ID {})"; sid:{}; rev:{}; classtype:bad-unknown;)\n'.format(self._snort_rule_action, domain, domain, id_, self._sid, self._snort_rule_revision)
            elif object_type == 'URI':
                for field in observable['fields']:
                    url = urlparse(field['value'])
                    text += '{} tcp any any -> $EXTERNAL_NET $HTTP_PORTS (flow:established,to_server; content:"{}"; http_header; nocase; uricontent:"{}"; nocase; msg:"CTI-Toolkit connection to potentially malicious url {} (ID {})"; sid:{}; rev:{}; classtype:bad-unknown;)\n'.format(self._snort_rule_action, url.netloc, url.path, url.geturl(), id_, self._sid, self._snort_rule_revision)
            self._sid += 1
        return text
