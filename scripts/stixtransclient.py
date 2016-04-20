"""
This script supports transforming indicators (observables) from a STIX Package
into the Bro Intelligence Format. It can interact with a TAXII server to obtain
the STIX package(s), or a STIX package file can be supplied.
"""

import sys
import logging
import configargparse
from libtaxii.scripts import TaxiiScript as ts 
#StringIO
from StringIO import StringIO

from certau.client import SimpleTaxiiClient
from certau.transform import StixTransform

def get_arg_parser():

    # Determine arguments and get input file
    parser = configargparse.ArgumentParser(
        default_config_files=['/etc/ctitoolkit.conf','~/.ctitoolkit'],
        description="Utility to extract observables from local STIX files or a TAXII server"
    )
    input_group = parser.add_argument_group('input')
    input_group.add_argument("-a", "--aus",
        action="store_true",
        help="input is CERT Australia formatted STIX"
    )
    input_group.add_argument("-c", "--ca",
        action="store_true",
        help="input is CCIRC formatted STIX"
    )
    input_group.add_argument("-n", "--nccic",
        action="store_true",
        help="input is NCCIC formatted STIX"
    )
    output_group = parser.add_argument_group('output')
    output_group.add_argument("-v", "--verbose",
        action="store_true",
        help="verbose output"
    )
    output_group.add_argument("-d", "--debug",
        action="store_true",
        help="Enable debug output"
    )
    output_group.add_argument("-b", "--bro",
        action="store_true",
        help="output bro intel framework formatted text"
    )
    output_group.add_argument("--bro_no_notice",
        action="store_true",
        help="Suppress bro intel notice framework messages"
    )
    output_group.add_argument("--misp",
        action="store_true",
        help="Feed output to MISP"
    )
    output_group.add_argument("-t", "--text",
        action="store_true",
        help="output delimited text"
    )
    output_group.add_argument("-f",
        dest="field_separator",
        default="|",
        help="Field separation character to use"
    )
    output_group.add_argument("-s", "--stats",
        action="store_true",
        help="display summary stats"
    )
    output_group.add_argument("-x", "--xml_output",
        dest="xml_output",
        help="Output XML to directory (must exist). Used with --taxii"
    )
    output_group.add_argument("--base_url",
        dest="base_url",
        help="Base URL for indicator source - used in bro and MISP output"
    )
    output_group.add_argument("--source",
        dest="source",
        default="unknown",
        help="Source of indicators - eg Hailataxii, CERT-AU"
    )
    output_group.add_argument("--title",
        dest="title",
        help="Title for package (if not included in STIX file)"
    )
    output_group.add_argument("--header",
        action="store_true",
        help="Include header row for text output"
    )
    parser.add_argument("--config",
        is_config_file=True,
        help="Configuration file to use"
    )
    taxii_group = parser.add_argument_group('taxii')
    taxii_group.add_argument("--hostname",
        dest="hostname",
        default="taxii.host.tld",
        help="Hostname of TAXII server. Defaults to taxii.host.tld"
    )
    taxii_group.add_argument("--username",
        dest="username",
        default="USER",
        help="Username for TAXII authentication"
    )
    taxii_group.add_argument("--password",
        dest="password",
        default = 'XXXXXXXXXXXXXXXXX',
        help="Password for TAXII authentication. Default value: guest"
    )
    taxii_group.add_argument("--key",
        dest="key",
        default="/etc/taxii/taxii-key.pem",
        help="PEM Key for TAXII authentication"
    )
    taxii_group.add_argument("--cert",
        dest="cert",
        default="/etc/taxii/taxii-cert.pem",
        help="PEM Certiificate file for authenticating to TAXII"
    )
    taxii_group.add_argument("--soltra",
        action="store_true",
        help="TAXII server is a SoltraEdge appliance"
    )
    taxii_group.add_argument("--ssl",
        action="store_true",
        help="Use SSL to connect to TAXII server"
    )
    taxii_group.add_argument("--path",
        dest="path",
        default="/services/poll/",
        help="Path on TAXII server. Defaults to  /services/poll/"
    )
    taxii_group.add_argument("--collection",
        dest="collection",
        default="default",
        help="Data Collection to poll. Defaults to 'default'."
    )
    taxii_group.add_argument("--begin-timestamp",
        dest="begin_ts",
        default=None,
        help="The begin timestamp (format: YYYY-MM-DDTHH:MM:SS.ssssss+/-hh:mm) "
            "for the poll request. Defaults to None."
    )
    taxii_group.add_argument("--end-timestamp",
        dest="end_ts",
        default=None,
        help="The end timestamp (format: YYYY-MM-DDTHH:MM:SS.ssssss+/-hh:mm) "
            "for the poll request. Defaults to None."
    )
    taxii_group.add_argument("--subscription-id",
        dest="subscription_id",
        default=None,
        help="The Subscription ID for the poll request. Defaults to None."
    )
    misp_group = parser.add_argument_group('misp')
    misp_group.add_argument("--misp_url",
        dest="misp_url",
        default="misp.host.tld",
        help="URL of MISP server. Defaults to misp.host.tld"
    )
    misp_group.add_argument("--misp_key",
        dest="misp_key",
        help="Token for accessing MISP instance"
    )
    misp_group.add_argument("--misp_distribution",
        dest="misp_distribution",
        default=0,
        type=int,
        help="Distribution group in MISP. Defaults to Your organisation only (0)"
    )
    misp_group.add_argument("--misp_threat",
        dest="misp_threat",
        default=4,
        type=int,
        help="Threat level in MISP. Defaults to undefined (4)"
    )
    misp_group.add_argument("--misp_analysis",
        dest="misp_analysis",
        default=0,
        type=int,
        help="Analysis phase in MISP. Defaults to initial (0)"
    )
    misp_group.add_argument("--misp_info",
        dest="misp_info",
        default='Automated STIX ingest',
        help="MISP event description. Defaults to STIX package title or Automated STIX ingest"
    )
    misp_group.add_argument("--misp_published",
        action="store_true",
        help="Set MISP published state to True"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--file",
        dest="file",
        default=None,
        help="Full path to XML file to process"
    )
    group.add_argument("--taxii",
        action="store_true",
        help="TAXII server and arguments for poll client"
    )
    return parser


if __name__ == "__main__":

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

    st = StixTransform(options)
    if options.taxii:
        logger.info("Processing a TAXII message")
        client = SimpleTaxiiClient(options)
        taxii_message = client.send_poll_request()

        if taxii_message:
            if options.xml_output:
                logger.debug("Writing XML to {}".format(options.xml_output))
                tsi = ts() # a TAXII Script instance - provides access to write_cbs...
                tsi.write_cbs_from_poll_response_11(taxii_message, options.xml_output)
            else:
                for cb in taxii_message.content_blocks:
                    logger.info("Processing TAXII content block")
		    try:
                        stringio = StringIO(cb.content)
                        st.process_input(stringio)
	            except:
		        logger.debug("Exception when processing TAXII message content: %s", cb.content)
		        pass
    else:
        logger.info("Processing file input")
        st.process_input(options.file)
