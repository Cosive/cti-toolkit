"""
This script supports transforming indicators (observables) from a STIX Package
into the Bro Intelligence Format. It can interact with a TAXII server to obtain
the STIX package(s), or a STIX package file can be supplied.
"""

import os
import sys
import logging
import pkg_resources
import dateutil
import urlparse
import pickle

import configargparse

from stix.extensions.marking import ais

from certau.source import StixFileSource, TaxiiPollResponseSource
from certau.transform import StixTextTransform, StixStatsTransform
from certau.transform import StixCsvTransform, StixBroIntelTransform
from certau.transform import StixMispTransform, StixSnortTransform
from certau.lib.stix.helpers import package_tlp
from certau.lib.taxii.client import SimpleTaxiiClient


def get_arg_parser():
    """Create an argument parser with options used by this script."""
    # Determine arguments and get input file
    parser = configargparse.ArgumentParser(
        default_config_files=['/etc/ctitoolkit.conf', '~/.ctitoolkit'],
        description=("Utility to extract observables from local STIX files " +
                     "or a TAXII server."),
    )
    # Global options
    global_group = parser.add_argument_group('global arguments')
    global_group.add_argument(
        "-c", "--config",
        is_config_file=True,
        help="configuration file to use",
    )
    global_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="verbose output",
    )
    global_group.add_argument(
        "-d", "--debug",
        action="store_true",
        help="enable debug output",
    )
    version = pkg_resources.require('cti-toolkit')[0].version
    global_group.add_argument(
        "-V", "--version",
        action="version",
        version="cti-toolkit {} by CERT Australia".format(version),
    )
    # Source options
    source_group = parser.add_argument_group('input (source) options')
    source_ex_group = source_group.add_mutually_exclusive_group(
        required=True,
    )
    source_ex_group.add_argument(
        "--file",
        nargs="+",
        help="obtain STIX packages from supplied files or directories",
    )
    source_ex_group.add_argument(
        "--taxii",
        action="store_true",
        help="poll TAXII server to obtain STIX packages",
    )
    # Output (transform) options
    output_group = parser.add_argument_group('output (transform) options')
    output_ex_group = output_group.add_mutually_exclusive_group(
        required=True,
    )
    output_ex_group.add_argument(
        "-s", "--stats",
        action="store_true",
        help="display summary statistics for each STIX package",
    )
    output_ex_group.add_argument(
        "-t", "--text",
        action="store_true",
        help="output observables in delimited text",
    )
    output_ex_group.add_argument(
        "-b", "--bro",
        action="store_true",
        help="output observables in Bro intel framework format",
    )
    output_ex_group.add_argument(
        "-m", "--misp",
        action="store_true",
        help="feed output to a MISP server",
    )
    output_ex_group.add_argument(
        "--snort",
        action="store_true",
        help="output observables in Snort rule format",
    )
    output_ex_group.add_argument(
        "-x", "--xml_output",
        help=("output XML STIX packages to the given directory " +
              "(use with --taxii)"),
    )
    # File source options
    file_group = parser.add_argument_group(
        title='file input arguments (use with --file)',
    )
    file_group.add_argument(
        "-r", "--recurse",
        action="store_true",
        help="recurse subdirectories when processing files.",
    )
    # TAXII source options
    taxii_group = parser.add_argument_group(
        title='taxii input arguments (use with --taxii)',
    )
    taxii_group.add_argument(
        "--poll-url",
        help="TAXII server's poll URL",
    )
    taxii_group.add_argument(
        "--hostname",
        help="hostname of TAXII server (deprecated - use --poll-url)",
    )
    taxii_group.add_argument(
        "--port",
        help="port of TAXII server (deprecated - use --poll-url)",
    )
    taxii_group.add_argument(
        "--ca_file",
        help="File containing CA certs of TAXII server",
    )
    taxii_group.add_argument(
        "--username",
        help="username for TAXII authentication",
    )
    taxii_group.add_argument(
        "--password",
        help="password for TAXII authentication",
    )
    taxii_group.add_argument(
        "--ssl",
        action="store_true",
        help="use SSL to connect to TAXII server (deprecated - use --poll-url)",
    )
    taxii_group.add_argument(
        "--key",
        help="file containing PEM key for TAXII SSL authentication",
    )
    taxii_group.add_argument(
        "--cert",
        help="file containing PEM certificate for TAXII SSL authentication",
    )
    taxii_group.add_argument(
        "--path",
        help="path on TAXII server for polling (deprecated - use --poll-url)",
    )
    taxii_group.add_argument(
        "--collection",
        help="TAXII collection to poll",
    )
    taxii_group.add_argument(
        "--begin-timestamp",
        help=("the begin timestamp (format: " +
              "YYYY-MM-DDTHH:MM:SS.ssssss+/-hh:mm) for the poll request"),
    )
    taxii_group.add_argument(
        "--end-timestamp",
        help=("the end timestamp (format: " +
              "YYYY-MM-DDTHH:MM:SS.ssssss+/-hh:mm) for the poll request"),
    )
    taxii_group.add_argument(
        "--subscription-id",
        help="a subscription ID for the poll request",
    )
    taxii_group.add_argument(
        "--state-file",
        help="file used to maintain latest poll times",
    )
    other_group = parser.add_argument_group(
        title='other output options',
    )
    other_group.add_argument(
        "-f", "--field-separator",
        help="field delimiter character/string to use in text output",
    )
    other_group.add_argument(
        "--header",
        action="store_true",
        help="include header row for text output",
    )
    other_group.add_argument(
        "--title",
        help="title for package (if not included in STIX file)",
    )
    other_group.add_argument(
        "--source",
        help="source of indicators - e.g. Hailataxii, CERT-AU (use with --bro)",
    )
    other_group.add_argument(
        "--bro-no-notice",
        action="store_true",
        help="suppress Bro intel notice framework messages (use with --bro)",
    )
    other_group.add_argument(
        "--base-url",
        help="base URL for indicator source (use with --bro)",
    )
    snort_group = parser.add_argument_group(
        title='snort output arguments (use with --snort)',
    )
    snort_group.add_argument(
        "--snort-initial-sid",
        default=5500000,
        type=int,
        help="initial Snort IDs to begin from - default: 5500000",
    )
    snort_group.add_argument(
        "--snort-rule-revision",
        default=1,
        type=int,
        help="revision of the Snort rule - default: 1",
    )
    snort_group.add_argument(
        "--snort-rule-action",
        choices=['alert', 'log', 'pass', 'activate', 'dynamic', 'drop',
                 'reject', 'sdrop'],
        default='alert',
        help="action used for Snort rules generated - default: 'alert'",
    )
    misp_group = parser.add_argument_group(
        title='misp output arguments (use with --misp)',
    )
    misp_group.add_argument(
        "--misp-url",
        help="URL of MISP server",
    )
    misp_group.add_argument(
        "--misp-key",
        help="token for accessing MISP instance",
    )
    misp_group.add_argument(
        "--misp-ssl",
        nargs='?',
        const=True,
        default=False,
        help=("validate SSL certificate of the MISP server "
              "(takes an optional CA certificate file)"),
    )
    misp_group.add_argument(
        "--misp-client-cert",
        help="Client certificate for authenticating to MISP instance",
    )
    misp_group.add_argument(
        "--misp-client-key",
        help="Private key associated with client certificate",
    )
    misp_group.add_argument(
        "--misp-distribution",
        default=0,
        type=int,
        help=("MISP distribution group - default: 0 " +
              "(your organisation only)"),
    )
    misp_group.add_argument(
        "--misp-threat",
        default=4,
        type=int,
        help="MISP threat level - default: 4 (undefined)",
    )
    misp_group.add_argument(
        "--misp-analysis",
        default=0,
        type=int,
        help="MISP analysis phase - default: 0 (initial)",
    )
    misp_group.add_argument(
        "--misp-info",
        #default='Automated STIX ingest',
        help="MISP event description",
    )
    misp_group.add_argument(
        "--misp-published",
        action="store_true",
        help="set MISP published state to True",
    )
    xml_group = parser.add_argument_group(
        title='XML (STIX) output arguments (use with --xml-output)',
    )
    xml_group.add_argument(
        "--ais-marking",
        action='store_true',
        help="add the AIS Marking structure to the STIX package",
    )
    xml_group.add_argument(
        "--ais-proprietary",
        action='store_true',
        help="set IsProprietary to True (otherwise False) in AIS Marking",
    )
    xml_group.add_argument(
        "--ais-consent",
        choices=['EVERYONE', 'NONE', 'USG'],
        default='NONE',
        help="consent level for submitter attribution in AIS Marking",
    )
    xml_group.add_argument(
        "--ais-default-tlp",
        choices=['WHITE', 'GREEN', 'AMBER'],
        default='AMBER',
        help='TLP used in AIS Marking when none found in package header',
    )
    xml_group.add_argument(
        "--ais-country",
        help="ISO-3661-1 alpha2 submitter country for AIS Marking",
    )
    xml_group.add_argument(
        "--ais-administrative-area",
        help="ISO-3661-2 submitter administrative area for AIS Marking",
    )
    xml_group.add_argument(
        "--ais-organisation",
        help="ISO-3661-2 submitter organisation for AIS Marking",
    )
    xml_group.add_argument(
        "--ais-industry-type",
        choices=[
            ais.CHEMICAL_SECTOR,
            ais.COMMERCIAL_FACILITIES_SECTOR,
            ais.COMMUNICATIONS_SECTOR,
            ais.CRITICAL_MANUFACTURING_SECTOR,
            ais.DAMS_SECTOR,
            ais.DEFENSE_INDUSTRIAL_BASE_SECTOR,
            ais.EMERGENCY_SERVICES_SECTOR,
            ais.ENERGY_SECTOR,
            ais.FINANCIAL_SERVICES_SECTOR,
            ais.FOOD_AND_AGRICULTURE_SECTOR,
            ais.GOVERNMENT_FACILITIES_SECTOR,
            ais.HEALTH_CARE_AND_PUBLIC_HEALTH_SECTOR,
            ais.INFORMATION_TECHNOLOGY_SECTOR,
            ais.NUCLEAR_REACTORS_MATERIALS_AND_WASTE_SECTOR,
            ais.OTHER,
            ais.TRANSPORTATION_SYSTEMS_SECTOR,
            ais.WATER_AND_WASTEWATER_SYSTEMS_SECTOR,
        ],
        default=ais.OTHER,
        help="submitter industry type for AIS Marking",
    )
    return parser

def _process_package(package, transform_class, transform_kwargs):
    """Loads a STIX package and runs a transform over it."""
    transform = transform_class(package, **transform_kwargs)
    if isinstance(transform, StixTextTransform):
        sys.stdout.write(transform.text())
    elif isinstance(transform, StixMispTransform):
        transform.publish()

def get_taxii_poll_state(filename, poll_url, collection):
    if os.path.isfile(filename):
        with open(filename, 'r') as state_file:
            poll_state = pickle.load(state_file)
            if isinstance(poll_state, dict) and poll_url in poll_state:
                if collection in poll_state[poll_url]:
                    return poll_state[poll_url][collection]
    return None

def set_taxii_poll_state(filename, poll_url, collection, timestamp):
    if timestamp is not None:
        poll_state = dict()
        if os.path.isfile(filename):
            with open(filename, 'r') as state_file:
                poll_state = pickle.load(state_file)
                if not isinstance(poll_state, dict):
                    raise Exception('unexpected content encountered when '
                                    'reading TAXII poll state file')
        if poll_url not in poll_state:
            poll_state[poll_url] = dict()
        poll_state[poll_url][collection] = timestamp
        with open(filename, 'w') as state_file:
            pickle.dump(poll_state, state_file)

def main():
    parser = get_arg_parser()
    options = parser.parse_args()

    logger = logging.getLogger(__name__)
    if options.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    elif options.verbose:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    logger.info("logging enabled")

    transform_kwargs = {}
    if options.stats:
        transform_class = StixStatsTransform
    elif options.text:
        transform_class = StixCsvTransform
        if options.field_separator:
            transform_kwargs['separator'] = options.field_separator
    elif options.bro:
        transform_class = StixBroIntelTransform
        transform_kwargs['do_notice'] = 'F' if options.bro_no_notice else 'T'
        if options.source:
            transform_kwargs['source'] = options.source
        if options.base_url:
            transform_kwargs['url'] = options.base_url
    elif options.misp:
        transform_class = StixMispTransform
        misp_kwargs = dict(
            misp_url=options.misp_url,
            misp_key=options.misp_key,
            misp_ssl=options.misp_ssl,
        )
        if options.misp_client_cert and options.misp_client_key:
            misp_kwargs['misp_cert'] = (options.misp_client_cert,
                                        options.misp_client_key)
        misp = StixMispTransform.get_misp_object(**misp_kwargs)
        transform_kwargs['misp'] = misp
        transform_kwargs['distribution'] = options.misp_distribution
        transform_kwargs['threat_level'] = options.misp_threat
        transform_kwargs['analysis'] = options.misp_analysis
        transform_kwargs['information'] = options.misp_info
        transform_kwargs['published'] = options.misp_published
    elif options.snort:
        transform_class = StixSnortTransform
        transform_kwargs['snort_initial_sid'] = options.snort_initial_sid
        transform_kwargs['snort_rule_revision'] = options.snort_rule_revision
        transform_kwargs['snort_rule_action'] = options.snort_rule_action
    elif options.xml_output:
        pass
    else:
        logger.error('Unable to determine transform type from options')

    if options.header:
        transform_kwargs['include_header'] = options.header

    if options.taxii:
        logger.info("Processing a TAXII message")

        taxii_client = SimpleTaxiiClient(
            username=options.username,
            password=options.password,
            key_file=options.key,
            cert_file=options.cert,
            ca_file=options.ca_file,
        )

        # Build the poll URL if it wasn't provided
        if options.poll_url is None:
            scheme = 'https' if options.ssl else 'http'
            netloc = options.hostname
            if options.port:
                netloc += ':{}'.format(options.port)
            url_parts = [scheme, netloc, options.path, '', '', '']
            poll_url = urlparse.urlunparse(url_parts)
        else:
            poll_url = options.poll_url

        # Use state file to grab begin_timestamp if possible
        # Otherwise, parse begin and end timestamps if provided
        if options.state_file and not options.begin_timestamp:
            begin_timestamp = get_taxii_poll_state(
                filename=options.state_file,
                poll_url=poll_url,
                collection=options.collection,
            )
        elif options.begin_timestamp:
            begin_timestamp = dateutil.parser.parse(options.begin_timestamp)
        else:
            begin_timestamp = None

        if options.end_timestamp:
            end_timestamp = dateutil.parser.parse(options.end_timestamp)
        else:
            end_timestamp = None

        # Create the poll request message
        poll_request = taxii_client.create_poll_request(
            collection=options.collection,
            subscription_id=options.subscription_id,
            begin_timestamp=begin_timestamp,
            end_timestamp=end_timestamp,
        )

        # Send the poll request
        poll_response = taxii_client.send_poll_request(poll_request, poll_url)
        source = TaxiiPollResponseSource(poll_response, poll_url)

        # Update the timestamp for the latest poll
        if options.state_file:
            end_timestamp_label = poll_response.inclusive_end_timestamp_label
            set_taxii_poll_state(
                filename=options.state_file,
                poll_url=options.poll_url,
                collection=options.collection,
                timestamp=end_timestamp_label.isoformat(),
            )

        logger.info("Processing TAXII content blocks")
    else:
        logger.info("Processing file input")
        source = StixFileSource(options.file, options.recurse)

    while True:
        package = source.next_stix_package()
        if package is not None:
            if options.xml_output:
                if options.ais_marking:
                    tlp = package_tlp(package) or options.ais_default_tlp
                    # Note add_ais_marking() removes existing markings
                    ais.add_ais_marking(
                        stix_package=package,
                        proprietary=options.ais_proprietary,
                        consent=options.ais_consent,
                        color=tlp,
                        country_name_code=options.ais_country,
                        country_name_code_type='ISO-3166-1_alpha-2',
                        industry_type=options.ais_industry_type,
                        admin_area_name_code=options.ais_administrative_area,
                        admin_area_name_code_type='ISO-3166-2',
                        organisation_name=options.ais_organisation,
                    )
                source.save_package(package, options.xml_output)
            else:
                _process_package(package, transform_class, transform_kwargs)
        else:
            break


if __name__ == '__main__':
    main()
