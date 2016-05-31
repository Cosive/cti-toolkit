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
        include_observable_id: a boolean value that indicates whether or not
            the observable id should be included in the text output
        snort_initial_sid: the initial snort rule number the script should start
            counting from.
        snort_rule_revision: a number indicating which revision of the snort rule
            should be generated. The default is 1 (first version of the rule).
        snort_rule_action: a value from the following list that indicates the rule
            action that all generated snort rules will have:
            [alert|log|pass|activate|dynamic|drop|reject|sdrop]
    """

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