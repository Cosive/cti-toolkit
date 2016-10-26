"""
This script supports transforming indicators (observables) from a STIX Package
into the Bro Intelligence Format. It can interact with a TAXII server to obtain
the STIX package(s), or a STIX package file can be supplied.
"""

import sys
import logging
import pkg_resources
from StringIO import StringIO

import configargparse
from stix.core import STIXPackage

from certau.source import StixFileSource, SimpleTaxiiClient
from certau.transform import StixTextTransform, StixStatsTransform
from certau.transform import StixCsvTransform, StixBroIntelTransform
from certau.transform import StixMispTransform, StixSnortTransform


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
        "--hostname",
        help="hostname of TAXII server",
    )
    taxii_group.add_argument(
        "--port",
        help="port of TAXII server",
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
        help="use SSL to connect to TAXII server",
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
        help="path on TAXII server for polling",
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
        help="source of indicators - e.g. Hailataxii, CERT-AU",
    )
    other_group.add_argument(
        "--bro-no-notice",
        action="store_true",
        help="suppress Bro intel notice framework messages (use with --bro)",
    )
    other_group.add_argument(
        "--base-url",
        help="base URL for indicator source - use with --bro or --misp",
    )
    snort_group = parser.add_argument_group(
        title='snort output arguments (use with --snort)',
    )
    snort_group.add_argument(
        "--snort-initial-sid",
        help="The initial Snort IDs to begin from (default: 5500000)",
    )
    snort_group.add_argument(
        "--snort-rule-revision",
        help="The revision of the Snort rule (default: 1)",
    )
    snort_group.add_argument(
        "--snort-rule-action",
        help=("Change all Snort rules generated to "
              "[alert|log|pass|activate|dynamic|drop|reject|sdrop]"),
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
    return parser


def _process_package(package, transform_class, transform_kwargs):
    """Loads a STIX package and runs a transform over it."""
    transform = transform_class(package, **transform_kwargs)
    if isinstance(transform, StixTextTransform):
        sys.stdout.write(transform.text())
    elif isinstance(transform, StixMispTransform):
        transform.publish()


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
    elif options.misp:
        transform_class = StixMispTransform
        misp = StixMispTransform.get_misp_object(
            options.misp_url, options.misp_key)
        transform_kwargs['misp'] = misp
        transform_kwargs['distribution'] = options.misp_distribution
        transform_kwargs['threat_level'] = options.misp_threat
        transform_kwargs['analysis'] = options.misp_analysis
        transform_kwargs['information'] = options.misp_info
        transform_kwargs['published'] = options.misp_published
    elif options.snort:
        transform_class = StixSnortTransform
        allowed_actions = ["alert", "log", "pass", "activate", "dynamic",
                           "drop", "reject", "sdrop"]
        if options.snort_initial_sid:
            transform_kwargs['snort_initial_sid'] = options.snort_initial_sid
        if options.snort_rule_revision:
            transform_kwargs['snort_rule_revision'] = options.snort_rule_revision
        if options.snort_rule_action and options.snort_rule_action in allowed_actions:
            transform_kwargs['snort_rule_action'] = options.snort_rule_action
    elif options.xml_output:
        pass
    else:
        logger.error('Unable to determine transform type from options')

    if options.header:
        transform_kwargs['include_header'] = options.header

    if options.taxii:
        logger.info("Processing a TAXII message")
        source = SimpleTaxiiClient(
            hostname=options.hostname,
            path=options.path,
            port=options.port,
            collection=options.collection,
            use_ssl=options.ssl,
            username=options.username,
            password=options.password,
            key_file=options.key,
            cert_file=options.cert,
            ca_file=options.ca_file,
            begin_ts=options.begin_timestamp,
            end_ts=options.end_timestamp,
            subscription_id=options.subscription_id,
        )
        source.send_poll_request()

        if options.xml_output:
            logger.debug("Writing XML to %s", options.xml_output)
            source.save_content_blocks(options.xml_output)
            return

        logger.info("Processing TAXII content blocks")
    else:
        logger.info("Processing file input")
        source = StixFileSource(options.file, options.recurse)

    while True:
        package = source.next_stix_package()
        if package:
            _process_package(package, transform_class, transform_kwargs)
        else:
            break


if __name__ == '__main__':
    main()
