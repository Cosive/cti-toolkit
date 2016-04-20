:mod:`stixtransclient.py`
=========================

Few systems can utilise indicators and observables when stored in STIX packages.
CERT Australia has developed a utility (``stixtransclient.py``) that allows the
atomic observables contained within a STIX package to be extracted and presented
in either a text delimited format, or in the `Bro Intel Framework
<http://blog.bro.org/2014/01/intelligence-data-and-bro_4980.html>`_ format.
The utility can also communicate with a `MISP
<http://www.misp-project.org/>`_ server and insert observables from a STIX
package into a new MISP event.

Examples
--------

Display summary statistics about the object types (observables) contained in
a STIX package (file)::

    $ stixtransclient.py --file CA-TEST-STIX.xml --stats

    ++++++++++++++++++++++++++++++++++++++++
    Summary statistics: CA-TEST-STIX (WHITE)
    ++++++++++++++++++++++++++++++++++++++++
    Address observables:                   2
    DomainName observables:                3
    EmailMessage observables:              2
    File observables:                      6
    HTTPSession observables:               1
    Mutex observables:                     3
    SocketAddress observables:             1
    URI observables:                       1
    WinRegistryKey observables:            1

Display observable details in text (delimited) format::

    $ stixtransclient.py --file CA-TEST-STIX.xml --text

    # CA-TEST-STIX (TLP:WHITE)

    # Address observables
    # id|category|address
    cert_au:Observable-fe5ddeac-f9b0-4488-9f89-bfbd9351efd4|ipv4-addr|158.164.39.51
    cert_au:Observable-ccccceac-f9b0-4488-9f89-bfbd9351efd4|ipv4-addr|111.222.33.44

    # DomainName observables
    # id|domain|domain_condition
    cert_au:Observable-6517027e-2cdb-47e8-b5c8-50c6044e42de|bad.domain.org|None
    cert_au:Observable-c97cc016-24b6-4d02-afc2-308742c722dc|dnsupdate.dyn.net|None
    cert_au:Observable-138a5be6-56b2-4d2d-af73-2d4865d6ff71|free.stuff.com|None

    # EmailMessage observables
    # id|fromaddr|fromaddr_condition|toaddr|toaddr_condition|subject|subject_condition|attachment_ref
    cert_au:Observable-b6770e76-7f05-48cb-a3de-7ba5fece8751|sender@domain.tld|Equals|None|None|None|None|None
    cert_au:Observable-31e5af27-2f71-4922-b49c-cfd3ddee2963|None|None|None|None|Important project details|Equals|cert_au:Observable-5d647351-f8cf-442f-9e5a-ba6967c16301

    # File observables
    # id|file_name|file_name_condition|hash_type|hashes
    cert_au:Observable-5d647351-f8cf-442f-9e5a-ba6967cccccc|filenameonly.doc|None|None|None
    cert_au:Observable-5d647351-f8cf-442f-9e5a-ba6967c16301|project.doc|Equals|MD5|1111111111b42b57f518197d930471d9
    cert_au:Observable-cccccd51-a524-483f-8f17-2e8ff8474d80|None|None|MD5|ccccccccccccccc33574c79829dc1ccf
    cert_au:Observable-84060d51-a524-483f-8f17-2e8ff8474d80|Execute_this.jar|Equals|MD5|11111111111111133574c79829dc1ccf
    cert_au:Observable-3ad6c684-80aa-4d92-9fef-7a9f70ccba95|malware.exe|Equals|MD5|11111111111111111f2601b4d21660fb
    cert_au:Observable-7cb2ac9f-4cae-443f-905d-0b01cb1faedc|VPN.exe|Equals|SHA256|11111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf
    cert_au:Observable-7cb2ac9f-4cae-443f-905d-0b01cb1faedc|VPN.exe|Equals|SHA1|893fb19ac24eabf9b1fe1ddd1111111111111111
    cert_au:Observable-7cb2ac9f-4cae-443f-905d-0b01cb1faedc|VPN.exe|Equals|MD5|11111111111111112977fa0588bd504a

    # HTTPSession observables
    # id|user_agent|user_agent_condition
    cert_au:Observable-6a733d83-5d19-4d17-a51f-5bcb4ebc860a|Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36|None

    # Mutex observables
    # id|mutex|mutex_condition
    NCCIC:Observable-01234567-6868-4ffd-babc-ba2ad0e34f43|WIN_ABCDEF|None
    NCCIC:Observable-abcdef01-3363-4533-a77c-10d71c371282|MUTEX_0001|None
    CCIRC-CCRIC:Observable-01234567-e44c-473a-85c6-fc6c2e781114|iurlkjashdk|Equals

    # SocketAddress observables
    # id|category|address|port_value|port_protocol
    CCIRC-CCRIC:Observable-01234567-2823-4d6d-8d77-bae10ca5bd97|ipv4-addr|183.82.180.95|2665|TCP

    # URI observables
    # id|uri|uri_condition
    cert_au:Observable-1a919136-ba69-4a28-9615-ad6ee37e88a5|http://host.domain.tld/path/file|None

    # WinRegistryKey observables
    # id|hive|hive_condition|key|key_condition|name|name_condition|data|data_condition
    cert_au:Observable-d0f4708e-4f2b-49c9-bc31-29e7119844e5|HKEY_CURRENT_USER\Software|Equals|\Microsoft\Windows\CurrentVersion\Run|Equals|hotkey|Equals|%APPDATA%\malware.exe -st|Equals

Display observables in the format used by the Bro Intelligence Framework
(with a header row explaining columns)::

    $ stixtransclient.py --file CA-TEST-STIX.xml --bro --header

    # indicator	indicator_type	meta.source	meta.url	meta.do_notice	meta.if_in	meta.whitelist
    158.164.39.51	Intel::ADDR	CERT-AU	https://www.cert.gov.au/	T	-	-
    111.222.33.44	Intel::ADDR	CERT-AU	https://www.cert.gov.au/	T	-	-
    bad.domain.org	Intel::DOMAIN	CERT-AU	https://www.cert.gov.au/	T	-	-
    dnsupdate.dyn.net	Intel::DOMAIN	CERT-AU	https://www.cert.gov.au/	T	-	-
    free.stuff.com	Intel::DOMAIN	CERT-AU	https://www.cert.gov.au/	T	-	-
    sender@domain.tld	Intel::EMAIL	CERT-AU	https://www.cert.gov.au/	T	-	-
    1111111111b42b57f518197d930471d9	Intel::FILE_HASH	CERT-AU	https://www.cert.gov.au/	T	-	-
    ccccccccccccccc33574c79829dc1ccf	Intel::FILE_HASH	CERT-AU	https://www.cert.gov.au/	T	-	-
    11111111111111133574c79829dc1ccf	Intel::FILE_HASH	CERT-AU	https://www.cert.gov.au/	T	-	-
    11111111111111111f2601b4d21660fb	Intel::FILE_HASH	CERT-AU	https://www.cert.gov.au/	T	-	-
    11111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf	Intel::FILE_HASH	CERT-AU	https://www.cert.gov.au/	T	-	-
    893fb19ac24eabf9b1fe1ddd1111111111111111	Intel::FILE_HASH	CERT-AU	https://www.cert.gov.au/	T	-	-
    11111111111111112977fa0588bd504a	Intel::FILE_HASH	CERT-AU	https://www.cert.gov.au/	T	-	-
    Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36	Intel::SOFTWARE	CERT-AU	https://www.cert.gov.au/	T	-	-
    183.82.180.95	Intel::ADDR	CCIRC	https://www.publicsafety.gc.ca/cnt/ntnl-scrt/cbr-scrt/ccirc-ccric-eng.aspx	T	-	-
    host.domain.tld/path/file	Intel::URL	CERT-AU	https://www.cert.gov.au/	T	-	-


Command line options (help)
---------------------------

The command line (and configuration) options for stixtransclient.py are
displayed below::

    $ stixtransclient.py -h
    
    usage: stixtransclient.py [-h] [-c CONFIG] [-v] [-d]
                              (--file FILE [FILE ...] | --taxii)
                              (-s | -t | -b | -m | -x XML_OUTPUT) [-r]
                              [--hostname HOSTNAME] [--username USERNAME]
                              [--password PASSWORD] [--ssl] [--key KEY]
                              [--cert CERT] [--path PATH]
                              [--collection COLLECTION]
                              [--begin-timestamp BEGIN_TIMESTAMP]
                              [--end-timestamp END_TIMESTAMP]
                              [--subscription-id SUBSCRIPTION_ID]
                              [-f FIELD_SEPARATOR] [--header] [--title TITLE]
                              [--source SOURCE] [--bro-no-notice]
                              [--base-url BASE_URL] [--misp-url MISP_URL]
                              [--misp-key MISP_KEY]
                              [--misp-distribution MISP_DISTRIBUTION]
                              [--misp-threat MISP_THREAT]
                              [--misp-analysis MISP_ANALYSIS]
                              [--misp-info MISP_INFO] [--misp-published]

    Utility to extract observables from local STIX files or a TAXII server. Args
    that start with '--' (eg. -v) can also be set in a config file
    (/etc/ctitoolkit.conf or ~/.ctitoolkit or specified via -c). The recognized
    syntax for setting (key, value) pairs is based on the INI and YAML formats
    (e.g. key=value or foo=TRUE). For full documentation of the differences from
    the standards please refer to the ConfigArgParse documentation. If an arg is
    specified in more than one place, then commandline values override config file
    values which override defaults.

    optional arguments:
      -h, --help            show this help message and exit

    global arguments:
      -c CONFIG, --config CONFIG
                            configuration file to use
      -v, --verbose         verbose output
      -d, --debug           enable debug output

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
      -x XML_OUTPUT, --xml_output XML_OUTPUT
                            output XML STIX packages to the given directory (use
                            with --taxii)

    file input arguments (use with --file):
      -r, --recurse         recurse subdirectories when processing files.

    taxii input arguments (use with --taxii):
      --hostname HOSTNAME   hostname of TAXII server
      --username USERNAME   username for TAXII authentication
      --password PASSWORD   password for TAXII authentication
      --ssl                 use SSL to connect to TAXII server
      --key KEY             file containing PEM key for TAXII SSL authentication
      --cert CERT           file containing PEM certificate for TAXII SSL
                            authentication
      --path PATH           path on TAXII server for polling
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

    other output options:
      -f FIELD_SEPARATOR, --field-separator FIELD_SEPARATOR
                            field delimiter character/string to use in text output
      --header              include header row for text output
      --title TITLE         title for package (if not included in STIX file)
      --source SOURCE       source of indicators - e.g. Hailataxii, CERT-AU
      --bro-no-notice       suppress Bro intel notice framework messages (use with
                            --bro)
      --base-url BASE_URL   base URL for indicator source - use with --bro or
                            --misp

    misp output arguments (use with --misp):
      --misp-url MISP_URL   URL of MISP server
      --misp-key MISP_KEY   token for accessing MISP instance
      --misp-distribution MISP_DISTRIBUTION
                            MISP distribution group - default: 0 (your
                            organisation only)
      --misp-threat MISP_THREAT
                            MISP threat level - default: 4 (undefined)
      --misp-analysis MISP_ANALYSIS
                            MISP analysis phase - default: 0 (initial)
      --misp-info MISP_INFO
                            MISP event description - default: 'Automated STIX
                            ingest'
      --misp-published      set MISP published state to True
