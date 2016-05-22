.. _configuration:

Configuration
=============

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

:mod:`ctitoolkit.conf` examples
-------------------------------

Some examples follow:

YETI::

    # Connect to the CERT Australia taxii server
    # Authenticate using certificate and user credentials
    # Poll indicators from the 'advisories' collection
    # Output data in Bro intel framework format
    source: YETI
    hostname: yeti.host.tld
    port: 8443 #if on non-standard port
    path: /services/poll/
    cert: /path/cert.pem
    key: /path/key.pem
    ca_file: /path/ca_file.pem
    username: _USER_
    password: _PASSWORD_
    collection: advisories
    base_url: https://source.host.com/advisories/
    ssl: true
    taxii: true
    bro: true

SoltraEdge::

    source: HAT
    hostname: hailataxii.com
    username: guest
    password: guest
    path: /taxii-data
    collection: guest.dataForLast_7daysOnly
    taxii: true
    soltra: true
    bro: true

FILE::

    # Process an STIX file and output to MISP
    source: FILE
    file: /path/to/stix/file.xml
    misp: true
    misp_url:http://misp.host.tld
    misp_key:keykeykeykeykeykeyke
