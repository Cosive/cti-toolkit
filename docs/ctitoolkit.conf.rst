:mod:`ctitoolkit.conf`
======================

The stixtransclient.py utility can read its configuration parameters
from the command line or configuration files located at:
 - /etc/ctitoolkit.conf
 - ~/.ctitoolkit

Any options that can be specified on the command line can be specified
in a configuration file. Command line options will always take precedence.

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
    cert: /path/cert.pem
    key: /path/key.pem
    username: _USER_
    password: _PASSWORD_
    collection: advisories
    base_url: https://source.host.com/advisories/
    ssl: true
    taxii: true
    bro: true
    aus: true

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

