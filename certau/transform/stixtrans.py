"""
This module provides the :py:class:`certau.transform.StixTransform` class
which supports converting indicators (observables) from a STIX package into
various other formats, including one suitable for importing indicators into
the Bro Intelligence Framework.
"""

from __future__ import print_function
import logging
import pprint
import re
import time

from datetime import datetime
from pymisp import PyMISP
from stix.core import STIXPackage

# Data collection imports
from collections import namedtuple
from collections import defaultdict
from collections import OrderedDict

# named tuples for storing observables
AddrObs = namedtuple("AddrObs", "id category address")
DomainObs = namedtuple("DomainObs", "id domain domain_condition")
EmailObs = namedtuple("EmailObs", "id fromaddr fromaddr_condition toaddr toaddr_condition subject subject_condition attachment_refs")
FileObs = namedtuple("FileObs", "id file_name file_name_condition hash_type hashes")
MailslotObs = namedtuple("MailslotObs", "id slot condition")
MutexObs = namedtuple("MutexObs", "id mutex condition")
UaObs = namedtuple("UaObs", "id user_agent user_agent_condition")
UrlObs = namedtuple("UrlObs", "id url url_condition")
WinRegKeyObs = namedtuple("WinRegKeyObs", "id hive hive_condition key key_condition name name_condition data data_condition")


class StixTransform(object):
    """
    When called with a STIX package and set of command line options
    this class will generate and output indicators appropriate to the arguments provided

    Args:
        options: an options object containing configuration options (see below)

    Options used by this class are listed under the heading 'Other Parameters'
    below (these are attributes of the options object).

    Other Parameters:
        stats: generate summary statistics for the STIX Package
        bro: generate output in the Bro Intel format
        text: generate raw text output
        aus: input is a CERT Australia STIX package
        nccic: input is a US-CERT (NCCIC) STIX package
        ca: input is a Canadian (CCIRC) STIX package
        soltra: input has been obtained from a Soltra TAXII instance
        field_separator: delimiter to use in output
        header: include header row in text output
    """

    def __init__(self, options):
        self._dict_package = None
        self._title = ''
        self._description = ''
        self._tlpmarking = 'AMBER'
        self._results_array = []
        self._results_dict = OrderedDict()
        self._args = None
        self._output = ''
        self._taxiimsg = None
        self._args = options
        self.logger = logging.getLogger()
        self.logger.debug("ST Object created")

    def process_input(self, stix_file):
        # Process the package header
        # extract and store the package title for later use
        self._results_array = []
        self._dict_package = STIXPackage.from_xml(stix_file).to_dict()
        try:
            if self._args.title:
                self._title = self._args.title
            else:
                self._title = self._dict_package['stix_header']['title']
                if self._args.aus:
                    self._title = self._title.replace("CA-", "")
        except:
            # if self._args.verbose:
            self.logger.warning("No title in package")

        try:
            self._tlpmarking = self._dict_package['stix_header']['handling'][0]['marking_structures'][0]['color']
        except:
            self.logger.warning("No TLP marking in package")

        try:
            self._description = self._dict_package['stix_header']['description']
        except:
            self.logger.warning("No description in package header")

        self._process_content()
        self._list_to_dict()

        self.logger.debug("Results array has %s elements", str(len(self._results_array)))
        self.logger.debug("Results dict has %s elements", str(len(self._results_dict)))

        if self._args.stats:
            print(self.generate_stats())
        if self._args.bro:
            print(self.display_bif())
        if self._args.text:
            print(self.display_delimited_results())
        if self._args.misp:
            self.publish_to_misp()

    def _list_to_dict(self):
        """Helper function to take a list containing multiple element types
        and convert to a default dict structure that allows indexing of values
        by type.
        """
        d = OrderedDict()
        for x in self._results_array:
            try:
                d[type(x)].append(x)
            except KeyError:
                d[type(x)] = [x]
        self._results_dict = d
        self.logger.debug("Results dict created:\n\t\t%s", d)

    def _process_fileobs(self, fileobs, obid):
        file_properties = fileobs['properties']
        hash_type = ''
        hashes = ''
        results = []
        self.logger.debug("File properties being processed: %s", file_properties)
        try:
            if 'value' in file_properties['file_name']:
                file_name = file_properties['file_name']['value']
            else:
                file_name = file_properties['file_name']
        except:
            file_name = None
        try:
            file_name_condition = file_properties['file_name']['condition']
        except:
            file_name_condition = None
        try:
            for h in file_properties['hashes']:
                self.logger.debug("Hashes: %s", h)
                try:
                    # Need to consider how to handle files with multiple
                    # hashes. Storing a single value simplifies csv
                    # processing
                    hash_type = h['type']['value']
                    try:
                        hashes = h['simple_hash_value']['value']
                    except:
                        hashes = h['simple_hash_value']
                    results.append(FileObs(obid, file_name, file_name_condition, hash_type, hashes))
                except:
                    self.logger.debug("Unable to process hash: %s", fileobs)
                    self.logger.warning("Unable to process hash value in observable: %s", obid)
        except:
            self.logger.debug("Unable to process hash: %s", fileobs)
            self.logger.warning("Unable to process hash value in observable: %s", obid)

        if file_name and not hashes:
            results.append(FileObs(obid, file_name, file_name_condition, hash_type, hashes))

        self.logger.debug("File observables processed: %s", results)
        return results

    def _process_emailobs(self, emailobs, obid):
        """ Given an email observable, command line arguments and an observable ID,
            this function will:
            - extract the email header details
            - extract file attachment references
            - return an EmailObs named tuple
        """
        attachment_refs = []
        email_properties = emailobs['properties']
        self.logger.debug("EmailProperties follow: " + str(email_properties))

        # Get header and list of references to attachments
        try:
            header = email_properties['header']
            # if self._args.debug:
            self.logger.debug("Email header {}".format(header))

        except:
            # if self._args.debug:
            self.logger.debug("No email header in object {}".format(obid))
        try:
            for ref in email_properties['attachments']:
                attachment_refs.append(ref['object_reference'])
        except:
            pass

        # Process the email header: note NCCIC uses the sender attribute for
        # from addresses

        try:
            if self._args.nccic or self._args.ca:
                the_fromaddr = header['sender']['address_value']['value']
            else:
                the_fromaddr = header['from']['address_value']['value']
        except:
            the_fromaddr = None
        try:
            if self._args.nccic or self._args.ca:
                the_fromaddr_condition = header['sender']['address_value']['condition']
            else:
                the_fromaddr_condition = header['from']['address_value']['condition']

        except:
            the_fromaddr_condition = None
        try:
            the_toaddr = header['to'][0]['address_value']
        except:
            the_toaddr = None
        try:
            the_toaddr_condition = header['to'][0]['address_value']['condition']
        except:
            the_toaddr_condition = None
        try:
            the_subject = header['subject']['value']
        except:
            the_subject = None
        try:
            the_subject_condition = header['subject']['condition']
        except:
            the_subject_condition = None

        return EmailObs(
            obid, the_fromaddr, the_fromaddr_condition,
            the_toaddr, the_toaddr_condition,
            the_subject, the_subject_condition,
            attachment_refs
        )

    def _process_uriobs(self, uriobs, obid):
        self.logger.debug(uriobs)
        url_properties = uriobs['properties']
        self.logger.debug("URL Properties: %s", url_properties)
        try:
            if 'value' in url_properties['value']:
                url = url_properties['value']['value']
            else:
                url = url_properties['value']
        except:
            url = None
        
        try:
            if 'condition' in url_properties['value']: 
                url_condition = url_properties['value']['condition']
            else:
                url_condition = url_properties['condition']
        except:
            url_condition = None

        # Bro intel format requires that the URL protocol field be removed
        if self._args.bro:
            regex = '^(https?|ftp)://'
            url = re.sub(regex, '', url)
        return UrlObs(obid, url, url_condition)

    def _process_domainobs(self, domainobs, obid):
        domain_properties = domainobs['properties']
        try:
            if 'value' in domain_properties['value']:
                domain = domain_properties['value']['value']
            else:
                domain = domain_properties['value']
        except:
            domain = None

        try:
            if 'condition' in domain_properties['value']:
                domain_condition = domain_properties['value']['condition']
            else:
                domain_condition = domain_properties['condition']
        except:
            domain_condition = None

        return DomainObs(obid, domain, domain_condition)

    def _process_socketobs(self, socketobs, obid):
        # This function currently only supports extraction of IP addresses
        # TODO: process full socket object

        self.logger.debug("Processing a SocketAddressObject %s", socketobs)
        address_properties = socketobs['properties']['ip_address']
        try:
            category = address_properties['category']
        except:
            category = None
        try:
            if 'value' in address_properties['address_value']:
                address = address_properties['address_value']['value']
            else:
                address = address_properties['address_value']
        except:
            address = None

        return AddrObs(obid, category, address)

    def _process_addressobs(self, addrobs, obid):
        address_properties = addrobs['properties']
        self.logger.debug("%s", address_properties)
        try:
            category = address_properties['category']
        except:
            category = None
        try:
            if 'value' in address_properties['address_value']:
                address = address_properties['address_value']['value']
            else:
                address = address_properties['address_value']
        except:
            address = None

        # Some STIX packages will represent address ranges as follows
        # <AddressObj:Address_Value condition="InclusiveBetween" apply_condition="ANY">139.162.157.0##comma##139.162.157.255</AddressObj:Address_Value>
        # the following conditional will exclude such ranges
        try:
            if not address_properties['address_value']['condition'] == 'InclusiveBetween':
                return AddrObs(obid, category, address)
        except:  # no condition value set
            return AddrObs(obid, category, address)

    def _process_uaobs(self, uaobs, obid):
        """

        """
        # TODO add condition matching for UA strings
        self.logger.debug("%s", uaobs)
        ua_properties = uaobs['properties']
        try:
            ua_properties['http_request_response'][0]['http_client_request']['http_request_header']['parsed_header']['user_agent']
        except:
            # No user agent in this - must be another http_request_response type of message
            return

        try:  # Soltra / CCIRC store these a little differently
            ua = ua_properties['http_request_response'][0]['http_client_request']['http_request_header']['parsed_header']['user_agent']['value']
        except:
            try:
                ua = ua_properties['http_request_response'][0]['http_client_request']['http_request_header']['parsed_header']['user_agent']
            except:
                ua = None
                self.logger.warning("Unable to extract user agent")

        try:  # Soltra / CCIRC store these a little differently
            ua_condition = ua_properties['http_request_response'][0]['http_client_request']['http_request_header']['parsed_header']['user_agent']['condition']
        except:
            ua_condition = None
            self.logger.warning("Unable to extract user agent match condition")
        return UaObs(obid, ua, ua_condition)

    def _process_mailslotobs(self, mailslotobs, obid):
        """

        """
        mailslot_properties = mailslotobs['properties']
        try:
            mailslot_name = mailslot_properties['name']['value']
        except:
            mailslot_name = None
            self.logger.warning("Unable to process MailslotObjectType mailslot name: %s", mailslotobs)
        try:
            mailslot_condition = mailslot_properties['name']['condition']
        except:
            mailslot_condition = None
            self.logger.warning("Unable to process MailslotObjectType mailslot condition: %s", mailslotobs)

        return MailslotObs(obid, mailslot_name, mailslot_condition)

    def _process_mutexobs(self, mutexobs, obid):
        """

        """
        mutex_properties = mutexobs['properties']
        try:
            if 'value' in mutex_properties['name']:
                mutex_name = mutex_properties['name']['value']
            else:
                mutex_name = mutex_properties['name']
        except:
            mutex_name = None
            self.logger.warning("Unable to process MutexObjectType mutex name: %s", mutexobs)
        try:
            mutex_condition = mutex_properties['name']['condition']
        except:
            mutex_condition = None
            self.logger.warning("Unable to process MutexObjectType mutex condition: %s", mutexobs)

        return MutexObs(obid, mutex_name, mutex_condition)

    def _process_wrkobs(self, wrkobs, obid):
        """
        Process a WinRegKey (wrk) observable
         - data
         - name
         - key
         - hive

        hive + key + name + data

        """
        wrk_properties = wrkobs['properties']['values'][0]
        try:
            wrk_name = wrk_properties['name']['value']
            wrk_name_condition = wrk_properties['name']['condition']
        except:
            wrk_name = None
            wrk_name_condition = None
            self.logger.warning("Unable to process WinRegistryKeyObject name: %s", wrkobs)

        try:
            wrk_data = wrk_properties['data']['value']
            wrk_data_condition = wrk_properties['data']['condition']
        except:
            wrk_data = None
            wrk_data_condition = None
            self.logger.warning("Unable to process WinRegistryKeyObject data: %s", wrkobs)

        try:
            wrk_hive = wrkobs['properties']['hive']['value']
            wrk_hive_condition = wrkobs['properties']['hive']['condition']
        except:
            wrk_hive = None
            wrk_hive_condition = None
            self.logger.warning("Unable to process WinRegistryKeyObject hive: %s", wrkobs)

        try:
            wrk_key = wrkobs['properties']['key']['value']
            wrk_key_condition = wrkobs['properties']['key']['condition']
        except:
            wrk_key = None
            wrk_key_condition = None
            self.logger.warning("Unable to process WinRegistryKeyObject key: %s", wrkobs)

        return WinRegKeyObs(
            obid,
            wrk_hive, wrk_hive_condition,
            wrk_key, wrk_key_condition,
            wrk_name, wrk_name_condition,
            wrk_data, wrk_data_condition
        )

    def _process_object(self, obj, objtype, obid):
        """ Given an object, type and ID this function generates
            a parsed object using the appropriate named tuple.

            When processing a FileObject, it will return an array
            of named tuple objects as a a single file object may have multiple hash values
        """
        parsed_object = None
        self.logger.debug("object value %s", obj)
        # Supported object types are:
        # - FileObjectType
        # - EmailMessageObjectType
        # - URIObjectType
        # - DomainNameObjectType
        # - AddressObjectType
        # - HTTPRequestResponseObjectType - User Agent only
        # - WindowsRegistryKeyObjectType

        # Note CCIRC uses the SocketAddress object type to represent IP addresses as follows:
        # {'id': 'CCIRC-CCRIC:SocketAddress-7dd93f17-b80c-40b4-bd44-c7db0530ef2e',
        #  'properties': {
        #                 'xsi:type': 'SocketAddressObjectType',
        #                 'ip_address': {
        #                                'category': 'ipv4-addr',
        #                                'xsi:type': 'AddressObjectType',
        #                                'address_value': {
        #                                                  'condition': 'Equals',
        #                                                  'value': '85.159.237.108'}}}}
        #
        # Additional work will need to be done to support other SocketAddress object types

        if objtype == "SocketAddressObjectType":
            try:
                parsed_object = self._process_socketobs(obj, obid)
            except:
                self.logger.warning("Attempt to process SocketAddressObjectType failed")
        elif objtype == "FileObjectType":
            parsed_object = self._process_fileobs(obj, obid)
        elif objtype.startswith("EmailMessage"):
            self.logger.debug("Processing email observable")
            parsed_object = self._process_emailobs(obj, obid)
        elif objtype == "URIObjectType":
            self.logger.debug("Processing URI object: %s", obj)
            parsed_object = self._process_uriobs(obj, obid)
        elif objtype == "DomainNameObjectType":
            parsed_object = self._process_domainobs(obj, obid)
        elif objtype == "AddressObjectType":
            parsed_object = self._process_addressobs(obj, obid)
        elif objtype == "HTTPSessionObjectType":
            parsed_object = self._process_uaobs(obj, obid)
        elif objtype == "WindowsMailslotObjectType":
            parsed_object = self._process_mailslotobs(obj, obid)
        elif objtype == "MutexObjectType":
            parsed_object = self._process_mutexobs(obj, obid)
        elif objtype == "WindowsRegistryKeyObjectType":
            parsed_object = self._process_wrkobs(obj, obid)
        else:
            self.logger.warning("Unsupported object type: %s", objtype)

        return parsed_object

    def _process_content(self):
        """ This method will parse through the dictified stix package provided as an input
            and populate named tuple obkects matching observables. This processing is conditional
            arguments as provided in the second parameter args.

            Returns an array of named tuples containing observables from the set:
            AddrObs, DomainObs, FileObs, UaObs, UrlObs, EmailObs
        """

        # Aim is to extract common elements of processing based on all STIX content
        # - xsi:type identification
        # - observable extraction
        # Where specific sources encode data in a unique way, args will be used to
        # perform conditional processing

        # Observables can be stored in the root of a package and referenced, or
        # stored directly within an indicator

        observable_list = []
        if self._args.soltra:
            # SoltraEdge stores indicators and referenced observables in separate files.
            # Soltra packages containing observables have the form:
            # Package
            #    Header
            #    Observables
            #        Observable -> object -> properties -> condition -> value
            try:
                observable_list = self._dict_package['observables']['observables']
                # if self._args.debug:
                self.logger.debug("Observables list generated %s", observable_list)
                self.logger.info("Observables list generated")

            except:
                # if self._args.debug:
                self.logger.warning("Unable to process soltra based observables")

        else:
            # Other systems will store observables in indicators or at the root of the package.
            try:
                observable_list = self._dict_package['observables']['observables']
                self.logger.info("Observables list generated %s", observable_list)

            except:
                self.logger.warning("Unable to generate observable list using self._dict_package['observables']['observables']")
                try:
                    observable_list = self._dict_package['indicators']
                    self.logger.info("Observables list generated")
                except:
                    self.logger.warning("Unable to generate observable list using self._dict_package['indicators']")

        for o in observable_list:
            obj = None
            obid = '-1'
            try:
                obid = o['id']
            except:
                # if self._args.debug:
                self.logger.debug("Unable to process observable %s", o)

            try:
                if 'object' in o:
                    obj = o['object']
                else:
                    obj = o['observable']['object']
            except:
                self.logger.debug("Unable to extract object {}.".format(obid))
                self.logger.warning("Unable to extract observable.")

            if obj:
                processed_obj = self._process_object(obj, obj['properties']['xsi:type'], obid)
                self.logger.debug("Processed object: %s", processed_obj)

                # Processed object may be a named tuple or an array of namedtuples (for FileObs)
                if isinstance(processed_obj, tuple):
                    self._results_array.append(processed_obj)
                else:
                    try:
                        for i in processed_obj:
                            self._results_array.append(i)
                    except:
                        pass

        # if self._args.debug:
        self.logger.debug(self._results_array)

    def generate_stats(self):
        """
        Returns the summary statistics for the STIX package as a string.
        Requires that the results array has already been populated.
        """
        self.logger.info("Generating STIX package statistics")

        friendly_type_names = OrderedDict()
        friendly_type_names[AddrObs] = 'Address'
        friendly_type_names[DomainObs] = 'Domain'
        friendly_type_names[EmailObs] = 'Email'
        friendly_type_names[FileObs] = 'File'
        friendly_type_names[MailslotObs] = 'Mailslot'
        friendly_type_names[MutexObs] = 'Mutex'
        friendly_type_names[UaObs] = 'User-Agent'
        friendly_type_names[UrlObs] = 'URL'
        friendly_type_names[WinRegKeyObs] = 'WinRegkey'

        stats = []

        line = "++++++++++++++++++++++++++++++++++++++++++\n"

        stats.append(line)
        stats.append("Summary statistics:\t" + self._title + "(" + self._tlpmarking + ")\n")
        stats.append(line)

        for t in friendly_type_names.keys():
            if t in self._results_dict:
                objects = self._results_dict[t]
                ids = set()
                for o in objects:
                    ids.add(o.id)
                stats.append('{0: <12} related observables: \t{1}\n'.format(
                    friendly_type_names[t], len(ids)
                ))
        stats.append(line)

        return ''.join(stats)

    def _generate_delimited_results(self, k):
        """ Helper function to construct a string of delimited results.
            Used by display_delimited_results.
            Returns a string representing the observables delimited by parameter passed in args
        """
        self.logger.info("Generating delimited results")
        return_str = []
        delimiter = self._args.field_separator
        results = self._results_dict[k]
        if results is None or len(results) == 0:
            return  # return_str
        self.logger.debug("results passed to display_results function" + str(results))

        o = results[0]
        header = ''
        if self._args.header:
            try:
                for hdr in o._fields:
                    header += hdr + delimiter
            except:
                return ''.join(return_str)
            return_str.append(header + "\n")
            return_str.append('='*len(header) + "\n")

        try:
            for o in results:
                for hdr in o._fields:
                    value = getattr(o, hdr)
                    if not isinstance(value, basestring):
                        value = pprint.pformat(value)
                    return_str.append(value + delimiter)
                return_str.append("\n")
            return_str.append("\n")
        except:
            pass

        return ''.join(return_str)

    def display_delimited_results(self):
        """Construct a delimited list of observables using options included in args.

        Returns:
            a string containing the output
        """
        return_str = []
        for k in self._results_dict.keys():
            if k != type(None):
                return_str.append(self._generate_delimited_results(k))
            self.logger.debug(return_str)
        return ''.join(return_str)

    def _generate_bif(self, k, url, source="UNKNOWN", do_notice="T"):
        """ Helper function to generate bro intel framework output
            Requires an observable type (k) and an optional reference URL, data source and a boolean
            to indicate whether notices should be raised when these observables are identified.

            Returns an Intel framework string representation of the observable type specified by k

            Issues requiring consideration:
             - bro intel framework does not support regular expressions - only matched based on
               'Equals' or None should be included
        """
        self.logger.info("Generating Bro intel framework results")

        if self._args.bro_no_notice:
            do_notice = "F"

        return_str = []
        results = self._results_dict[k]
        def print_intel(o, attribute, indicator_type, default='-'):
            value = getattr(o, attribute)
            if not isinstance(value, basestring):
                value = pprint.pformat(value)
            _str = '{}\n'.format('\t'.join((
                value, indicator_type, source, url, do_notice, default, default
            )))
            return _str

        for o in results:
            if isinstance(o, AddrObs):
                indicator_type = "Intel::ADDR"
                attribute = 'address'
                return_str.append(print_intel(o, attribute, indicator_type))

            if isinstance(o, DomainObs):
                indicator_type = "Intel::DOMAIN"
                if o.domain_condition == "Equals" or o.domain_condition is None:
                    attribute = 'domain'
                    return_str.append(print_intel(o, attribute, indicator_type))

            if isinstance(o, UrlObs):
                indicator_type = "Intel::URL"
                if o.url_condition == "Equals" or o.url_condition is None:
                    attribute = 'url'
                    return_str.append(print_intel(o, attribute, indicator_type))

            if isinstance(o, EmailObs):
                indicator_type = "Intel::EMAIL"
                if o.fromaddr is not None and o.fromaddr_condition == 'Equals':
                    attribute = 'fromaddr'
                    return_str.append(print_intel(o, attribute, indicator_type))
                if o.toaddr is not None and o.toaddr_condition == 'Equals':
                    attribute = 'toaddr'
                    return_str.append(print_intel(o, attribute, indicator_type))

            if isinstance(o, FileObs):
                indicator_type = "Intel::FILE_HASH"
                if o.hashes != '':
                    attribute = 'hashes'
                    return_str.append(print_intel(o, attribute, indicator_type))

            if isinstance(o, UaObs):
                indicator_type = 'Intel::SOFTWARE'
                attribute = 'user_agent'
                # Bro does not support regex matching for user agents
                if o.user_agent_condition != 'FitsPattern':
                    return_str.append(print_intel(o, attribute, indicator_type))

        return ''.join(return_str)

    def display_bif(self):
        return_str = []
        input_source = ''
        if self._args.header:
            return_str.append("#fields\tindicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\tmeta.if_in\tmeta.whitelist\n")
        for k in self._results_dict.keys():
            if k != type(None):
                if self._args.nccic:
                    url = "https://www.us-cert.gov" if not self._args.base_url else self._args.base_url
                    return_str.append(self._generate_bif(k, url, source="NCCIC"))
                elif self._args.ca:
                    url = "https://www.publicsafety.gc.ca/cnt/ntnl-scrt/cbr-scrt/ccirc-ccric-eng.aspx" if not self._args.base_url else self._args.base_url
                    return_str.append(self._generate_bif(k, url, source="CCIRC"))
                elif self._args.aus:
                    url = "https://www.cert.gov.au/" if not self._args.base_url else self._args.base_url
                    return_str.append(self._generate_bif(k, url+self._title, source="CERT-AU"))
                else:
                    if self._args.file:
                        input_source = self._args.file
                    if self._args.taxii and self._args.hostname:
                        input_source = self._args.hostname
                    return_str.append(self._generate_bif(k, url=input_source, source=self._args.source))

        return ''.join(return_str)

    def publish_to_misp(self):
        self.logger.info("Publishing results to MISP")

        misp_info = ''
        if self._title and self._args.source:
            misp_info = self._args.source + ':' + self._title + ' | ' + self._description
        elif self._args.misp_info:
            misp_info = self._args.misp_info
        else:
            misp_info = 'Undefined'

        self.logger.debug("Connecting to MISP using the following parameters: %s \n %s", self._args.misp_url, self._args.misp_key)
        misp = PyMISP(self._args.misp_url, self._args.misp_key, False, 'json')

        # strptime does not currently support timezone offsets in Python 2.x
        # - need to truncate the string
        try:
            dt = datetime.strptime(self._dict_package['timestamp'][:19], '%Y-%m-%dT%H:%M:%S')
            self.logger.debug(dt.strftime('%Y-%m-%d'))
        except:
            self.logger.warning("%s has no timestamp.", self._title)
            dt = datetime.now()

        event = misp.new_event(
            self._args.misp_distribution,
            self._args.misp_threat,
            self._args.misp_analysis,
            misp_info,
            date=dt.strftime('%Y-%m-%d'),
            published=False if not self._args.misp_published else self._args.misp_published
        )

        self.logger.debug(event)

        time.sleep(0.2)

        for k in self._results_dict.keys():
            for o in self._results_dict[k]:
                if isinstance(o, AddrObs):
                    self.logger.debug(getattr(o, 'address'))
                    misp.add_ipdst(event, getattr(o, 'address'))

                if isinstance(o, DomainObs):
                    self.logger.debug(getattr(o, 'domain'))
                    misp.add_domain(event, getattr(o, 'domain'))

                if isinstance(o, UrlObs):
                    self.logger.debug(getattr(o, 'url'))
                    misp.add_url(event, getattr(o, 'url'))

                if isinstance(o, EmailObs):
                    if o.fromaddr and o.fromaddr_condition == 'Equals':
                        self.logger.debug(getattr(o, 'fromaddr'))
                        misp.add_email_src(event, getattr(o, 'fromaddr'))
                    if o.subject and o.subject_condition == 'Equals':
                        self.logger.debug(getattr(o, 'subject'))
                        misp.add_email_subject(event, getattr(o, 'subject'))

                if isinstance(o, FileObs):
                    if o.hashes:
                        self.logger.debug(getattr(o, 'hashes'))
                        if o.hash_type == 'MD5':
                            misp.add_hashes(event, md5=getattr(o, 'hashes'))
                        if o.hash_type == 'SHA1':
                            misp.add_hashes(event, sha1=getattr(o, 'hashes'))
                        if o.hash_type == 'SHA256':
                            misp.add_hashes(event, sha256=getattr(o, 'hashes'))

                if isinstance(o, UaObs):
                    if o.user_agent_condition != 'FitsPattern':
                        self.logger.debug(getattr(o, 'user_agent'))
                        misp.add_useragent(event, getattr(o, 'user_agent'))

                if isinstance(o, WinRegKeyObs):
                    # What combinations are possible here? Current assumption is that you will
                    # have a regkey (hive + key) or
                    # a regkey (hive + key) and regvalue (name + data)
                    #
                    # May need more granular options depending on data provided

                    self.logger.debug(o)

                    regkey = None
                    regvalue = None

                    if ((o.hive_condition == o.key_condition == 'Equals') or
                        (o.hive_condition == o.key_condition == 'None')):
                        regkey = o.hive + o.key

                    if ((o.data_condition == o.name_condition == 'Equals') or
                        (o.data_condition == o.name_condition == 'None')):
                        regvalue = o.name + '\\' + o.data

                    if regkey:
                        if regvalue:
                            misp.add_regkey(event, regkey, regvalue)
                        else:
                            misp.add_regkey(event, regkey)

                time.sleep(0.2)
