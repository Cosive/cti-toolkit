.. _configuration:

Configuration examples
======================

The ``stixtransclient.py`` utility can read its configuration parameters from
the following locations:
- /etc/ctitoolkit.conf
- ~/.ctitoolkit
- a configuration file specified using the ``--config`` command line option
- as explicit command line parameters

If a configuration option is specified in more than one of the above locations
the last one processed will take precedence. Options are processed in the
order listed above.

Any options that can be specified on the command line can be specified
in a configuration file.

Examples explaining which options to use for various *sources* and *transforms*
are provided below.
It is possible to cut and paste the relevant options into a configuration
file and then run ``stixtransclient.py`` with that configuration file
using the ``--config`` command line option. Currently ``stixtransclient.py``
can only read STIX packages from a single source and output using a single
transform.

STIX packages from a TAXII server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    # Poll a collection on TAXII server
    --taxii
    --poll-url https://taxii.cert.gov.au/services/poll/
    --collection advisories

    # Provide credentials for authenticating to the TAXII server
    # Credentials are optional (depending on server requirements)
    --username alice
    --password alice_password
    --key /home/alice/keys/alice_key_file.pem
    --cert /home/alice/keys/alice_cert_file.pem

    # Save the poll state in a file so that subsequent polls will
    # only obtain STIX packages that have not yet been downloaded
    --state-file /home/alice/.taxii_poll_state

    # Alternatively, specify a begin and/or end timestamp for the poll
    # --begin-timestamp 2016-07-13T12:11:10+00:00
    # --end-timestamp   2016-08-27T05:17:55+00:00

STIX packages from files
~~~~~~~~~~~~~~~~~~~~~~~~

STIX packages can be read from a single file or from a directory and,
optionally, subdirectories. Any files encountered that do not contain
a valid STIX package will cause an error to be displayed, but processing
will continue::

    # Read a package from a single file
    --file some_stix_file.xml

    # Alternatively, read all the files in a directory
    # --file some_directory_containing_stix_files

    # Alternatively, read all the files in a directory and its subdirectories
    # --file some_directory
    # --recurse

Output statistics
~~~~~~~~~~~~~~~~~

::

    # Display statistics (per STIX package)
    --stats

Output text (CSV)
~~~~~~~~~~~~~~~~~

::

    # Text (CSV) output - default separator is '|'
    --text

    # Optionally, specify a separator
    # --field-separator ','

Output XML files (STIX)
~~~~~~~~~~~~~~~~~~~~~~~

Output STIX packages in files. This is useful for saving the results
of polling a TAXII server. ``stixtransclient.py`` also allows the
addition of the US DHS AIS Handling Structure to a package, prior to saving
it to a file (see: https://www.us-cert.gov/ais for more details about the
AIS program).

See ``stixtransclient.py -h`` for the full list of legal values for the
AIS settings below::

    # XML (STIX) output - specify a directory for the output
    --xml-output output_directory

    # Optionally, include an AIS Marking in the STIX packages
    # --ais-marking
    # Set the 'IsProprietary' flag in the AIS Marking
    # --ais-proprietary
    # Set the consent level for submitter attribution (EVERYONE, NONE, USG)
    # --ais-consent USG
    # Set the TLP to use if the source package does not contain one
    # --ais-default-tlp AMBER
    # Set the submitter country (ISO-3661-1)
    # --ais-country AU
    # Set the submitter administrative area (ISO-3661-2)
    # --ais-administrative-area AU-ACT
    # Set the submitter organisation
    # --ais-organisation 'CERT Australia'
    # Set the submitter industry type
    # --ais-industry-type 'Other'

Output to a MISP server
~~~~~~~~~~~~~~~~~~~~~~~

A new MISP event will be created for each STIX package::

    # MISP output - specify the URL and an API key
    --misp
    --misp-url https://misp.example.com/
    --misp-key rnNB3NdKE5D0LzdKyxjzQsJ0nhys9a3NXHniLAKq

    # Authentication options (optional)
    # A client TLS key and certificate
    # --misp-key alice_misp_key.pem
    # --misp-cert alice_misp_cert.pem
    # Verify the server certificate
    # --misp-ssl
    # Provide a file containing the CA's certificate
    # --misp-ssl ca_certificate.pem

    # Set MISP event values (optional)
    # Distribution (default 0 - your organisation only)
    # --misp-distribution 1
    # Threat (default 4 - undefined)
    # --misp-threat 3
    # Analysis (default 0 - initial)
    # --misp-analysis 2
    # Information (taken from package title and description if available)
    # --misp-info 'This is the event description'
    # Published (default False)
    # --misp-published

Output Bro Intel Framework rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    # BIF output
    --bro

    # Suppress Bro notices for matches (optional)
    # --bro-no-notice

    # Provide source and/or url fields for Bro output (optional)
    # --source Hailataxii
    # --base-url http://hailataxii.com/

Output Snort or Suricata rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    # Snort output
    --snort

    # Other snort options (optional)
    # SID of first rule (incremented in subsequent rules)
    # --snort-initial-sid 6600000
    # A revision number for the rules (default 1)
    # --snort-rule-revision 3
    # The snort action on a match (default 'alert')
    # --snort-action drop

General output options
~~~~~~~~~~~~~~~~~~~~~~

The following options can be used with all output transforms::

    # Specify a default title, description, or TLP to be used
    # when the STIX package does not contain these values
    # --default-title 'Some package title'
    # --default-description 'A package description'
    # --default-tlp 'WHITE'
