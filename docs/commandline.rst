.. _commandline:

Command line options
====================

The command line (and configuration) options for ``stixtransclient.py`` are
displayed below. For a more detailed explanation, including examples, please
see the :ref:`configuration` page::

    $ stixtransclient.py -h

    usage: stixtransclient.py [-h] [-c CONFIG] [-v] [-d] [-V]
                              (--file FILE [FILE ...] | --taxii)
                              (-s | -t | -b | -m | --snort | -x XML_OUTPUT) [-r]
                              [--poll-url POLL_URL] [--hostname HOSTNAME]
                              [--port PORT] [--ca_file CA_FILE]
                              [--username USERNAME] [--password PASSWORD] [--ssl]
                              [--key KEY] [--cert CERT] [--path PATH]
                              [--collection COLLECTION]
                              [--begin-timestamp BEGIN_TIMESTAMP]
                              [--end-timestamp END_TIMESTAMP]
                              [--subscription-id SUBSCRIPTION_ID]
                              [--state-file STATE_FILE] [-f FIELD_SEPARATOR]
                              [--header] [--default-title DEFAULT_TITLE]
                              [--default-description DEFAULT_DESCRIPTION]
                              [--default-tlp {WHITE,GREEN,AMBER,RED}]
                              [--source SOURCE] [--bro-no-notice]
                              [--base-url BASE_URL]
                              [--snort-initial-sid SNORT_INITIAL_SID]
                              [--snort-rule-revision SNORT_RULE_REVISION]
                              [--snort-rule-action {alert,log,pass,activate,dynamic,drop,reject,sdrop}]
                              [--misp-url MISP_URL] [--misp-key MISP_KEY]
                              [--misp-ssl [MISP_SSL]]
                              [--misp-client-cert MISP_CLIENT_CERT]
                              [--misp-client-key MISP_CLIENT_KEY]
                              [--misp-distribution MISP_DISTRIBUTION]
                              [--misp-threat MISP_THREAT]
                              [--misp-analysis MISP_ANALYSIS]
                              [--misp-info MISP_INFO] [--misp-published]
                              [--ais-marking] [--ais-proprietary]
                              [--ais-consent {EVERYONE,NONE,USG}]
                              [--ais-default-tlp {WHITE,GREEN,AMBER,RED}]
                              [--ais-country AIS_COUNTRY]
                              [--ais-administrative-area AIS_ADMINISTRATIVE_AREA]
                              [--ais-organisation AIS_ORGANISATION]
                              [--ais-industry-type {Chemical Sector,Commercial Facilities Sector,Communications Sector,Critical Manufacturing Sector,Dams Sector,Defense Industrial Base Sector,Emergency Services Sector,Energy Sector,Financial Services Sector,Food and Agriculture Sector,Government Facilities Sector,Healthcare and Public Health Sector,Information Technology Sector,Nuclear Reactors, Materials, and Waste Sector,Other,Transportation Systems Sector,Water and Wastewater Systems Sector}]

    Utility to extract observables from local STIX files or a TAXII server. Args
    that start with '--' (eg. -v) can also be set in a config file
    (/etc/ctitoolkit.conf or ~/.ctitoolkit or specified via -c). Config file
    syntax allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at
    https://goo.gl/R74nmi). If an arg is specified in more than one place, then
    commandline values override config file values which override defaults.

    optional arguments:
      -h, --help            show this help message and exit

    global arguments:
      -c CONFIG, --config CONFIG
                            configuration file to use
      -v, --verbose         verbose output
      -d, --debug           enable debug output
      -V, --version         show program's version number and exit

    input (source) options:
      --file FILE [FILE ...]
                            obtain STIX packages from supplied files or
                            directories
      --taxii               poll TAXII server to obtain STIX packages

    output (transform) options:
      -s, --stats           display summary statistics for each STIX package
      -t, --text            output observables in delimited text
      -b, --bro             output observables in Bro intel framework format
      -m, --misp            feed output to a MISP server
      --snort               output observables in Snort rule format
      -x XML_OUTPUT, --xml_output XML_OUTPUT
                            output XML STIX packages to the given directory (use
                            with --taxii)

    file input arguments (use with --file):
      -r, --recurse         recurse subdirectories when processing files.

    taxii input arguments (use with --taxii):
      --poll-url POLL_URL   TAXII server's poll URL
      --hostname HOSTNAME   hostname of TAXII server (deprecated - use --poll-url)
      --port PORT           port of TAXII server (deprecated - use --poll-url)
      --ca_file CA_FILE     File containing CA certs of TAXII server
      --username USERNAME   username for TAXII authentication
      --password PASSWORD   password for TAXII authentication
      --ssl                 use SSL to connect to TAXII server (deprecated - use
                            --poll-url)
      --key KEY             file containing PEM key for TAXII SSL authentication
      --cert CERT           file containing PEM certificate for TAXII SSL
                            authentication
      --path PATH           path on TAXII server for polling (deprecated - use
                            --poll-url)
      --collection COLLECTION
                            TAXII collection to poll
      --begin-timestamp BEGIN_TIMESTAMP
                            the begin timestamp (format: YYYY-MM-
                            DDTHH:MM:SS.ssssss+/-hh:mm) for the poll request
      --end-timestamp END_TIMESTAMP
                            the end timestamp (format: YYYY-MM-
                            DDTHH:MM:SS.ssssss+/-hh:mm) for the poll request
      --subscription-id SUBSCRIPTION_ID
                            a subscription ID for the poll request
      --state-file STATE_FILE
                            file used to maintain latest poll times

    other output options:
      -f FIELD_SEPARATOR, --field-separator FIELD_SEPARATOR
                            field delimiter character/string to use in text output
      --header              include header row for text output
      --default-title DEFAULT_TITLE
                            title for package (if not included in STIX file)
      --default-description DEFAULT_DESCRIPTION
                            description for package (if not included in STIX file)
      --default-tlp {WHITE,GREEN,AMBER,RED}
                            TLP colour for package (if not included in STIX file)
      --source SOURCE       source of indicators - e.g. Hailataxii, CERT-AU (use
                            with --bro)
      --bro-no-notice       suppress Bro intel notice framework messages (use with
                            --bro)
      --base-url BASE_URL   base URL for indicator source (use with --bro)

    snort output arguments (use with --snort):
      --snort-initial-sid SNORT_INITIAL_SID
                            initial Snort IDs to begin from - default: 5500000
      --snort-rule-revision SNORT_RULE_REVISION
                            revision of the Snort rule - default: 1
      --snort-rule-action {alert,log,pass,activate,dynamic,drop,reject,sdrop}
                            action used for Snort rules generated - default:
                            'alert'

    misp output arguments (use with --misp):
      --misp-url MISP_URL   URL of MISP server
      --misp-key MISP_KEY   token for accessing MISP instance
      --misp-ssl [MISP_SSL]
                            validate SSL certificate of the MISP server (takes an
                            optional CA certificate file)
      --misp-client-cert MISP_CLIENT_CERT
                            Client certificate for authenticating to MISP instance
      --misp-client-key MISP_CLIENT_KEY
                            Private key associated with client certificate
      --misp-distribution MISP_DISTRIBUTION
                            MISP distribution group - default: 0 (your
                            organisation only)
      --misp-threat MISP_THREAT
                            MISP threat level - default: 4 (undefined)
      --misp-analysis MISP_ANALYSIS
                            MISP analysis phase - default: 0 (initial)
      --misp-info MISP_INFO
                            MISP event description
      --misp-published      set MISP published state to True

    XML (STIX) output arguments (use with --xml-output):
      --ais-marking         add the AIS Marking structure to the STIX package
      --ais-proprietary     set IsProprietary to True (otherwise False) in AIS
                            Marking
      --ais-consent {EVERYONE,NONE,USG}
                            consent level for submitter attribution in AIS Marking
      --ais-default-tlp {WHITE,GREEN,AMBER,RED}
                            TLP used in AIS Marking when none found in package
                            header
      --ais-country AIS_COUNTRY
                            ISO-3661-1 alpha2 submitter country for AIS Marking
      --ais-administrative-area AIS_ADMINISTRATIVE_AREA
                            ISO-3661-2 submitter administrative area for AIS
                            Marking
      --ais-organisation AIS_ORGANISATION
                            ISO-3661-2 submitter organisation for AIS Marking
      --ais-industry-type {Chemical Sector,Commercial Facilities Sector,Communications Sector,Critical Manufacturing Sector,Dams Sector,Defense Industrial Base Sector,Emergency Services Sector,Energy Sector,Financial Services Sector,Food and Agriculture Sector,Government Facilities Sector,Healthcare and Public Health Sector,Information Technology Sector,Nuclear Reactors, Materials, and Waste Sector,Other,Transportation Systems Sector,Water and Wastewater Systems Sector}
                            submitter industry type for AIS Marking
