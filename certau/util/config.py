from __future__ import absolute_import  # avoid collision on 'stix'

import configargparse

from stix.extensions.marking import ais

from .. import version_string
from .stix.helpers import TLP_COLOURS


def get_arg_parser():
    """Create an argument parser with required options."""

    # Determine arguments and get input file
    parser = configargparse.ArgumentParser(
        default_config_files=[
            '/etc/ctitoolkit.conf',
            '~/.ctitoolkit',
        ],
        description=("Utility to extract observables from local STIX files "
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
    global_group.add_argument(
        "-V", "--version",
        action="version",
        version="{} (by CERT Australia)".format(version_string),
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
        help=("use SSL to connect to TAXII server "
              "(deprecated - use --poll-url instead)"),
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
        help=("URL path on TAXII server for polling "
              "(deprecated - use --poll-url)"),
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

    # Other output options
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
        "--default-title",
        help="title for package (if not included in STIX file)",
    )
    other_group.add_argument(
        "--default-description",
        help="description for package (if not included in STIX file)",
    )
    other_group.add_argument(
        "--default-tlp",
        choices=TLP_COLOURS,
        default="AMBER",
        help="TLP colour for package (if not included in STIX file)",
    )
    other_group.add_argument(
        "--source",
        help=("source of indicators - e.g. Hailataxii, CERT-AU "
              "(use with --bro)"),
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

    # Snort output options
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

    # MISP output options
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
        # default='Automated STIX ingest',
        help="MISP event description",
    )
    misp_group.add_argument(
        "--misp-published",
        action="store_true",
        help="set MISP published state to True",
    )

    # File (XML) output options
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
        choices=TLP_COLOURS,
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
        help="submitter organisation for AIS Marking",
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
