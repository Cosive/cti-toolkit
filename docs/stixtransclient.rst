:mod:`stixtransclient.py`
========================

Few systems can utilise indicators and observables when stored in STIX packages.
CERT Australia has developed a utility (stixtransclient.py) that allows the
atomic observables contained within a STIX package to be extracted and presented
in either a text delimited format, or in the `Bro Intel Framework
<http://blog.bro.org/2014/01/intelligence-data-and-bro_4980.html>`_ format.

:mod:`stixtransclient.py` overview
----------------------------------

Example usage::
    .. code-block:: none
        :emphasize-lines: 1,27,28

        $ stixtransclient.py -a -s -b --file ca-XXXX-YYY-stix.xml
    
        ++++++++++++++++++++++++++++++++++++++
        Summary statistics for XXXX-YYY
        ++++++++++++++++++++++++++++++++++++++
        File related observables: 	9
        Email related observables: 	8
        Domain related observables: 	3
        Address related observables: 	3
        URL related observables: 	533
        ++++++++++++++++++++++++++++++++++++++
    
        #fields	indicator	indicator_type	meta.source	meta.url	meta.do_notice	meta.if_in	meta.whitelist
        216.213.78.72	Intel::ADDR	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        88.211.147.62	Intel::ADDR	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        73.189.141.135	Intel::ADDR	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        38stalprof.com.ua/includes/domit/src.php	Intel::URL	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        ferma.az/incfiles/classes/iddx.php	Intel::URL	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        intimit.ru/includes/phpmailer/source.php	Intel::URL	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        jetc.com/illegal_access_folder/source.php	Intel::URL	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        keeleux.com/wp/wp-includes/idx.php	Intel::URL	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        shopcode.net/wp-includes/pomo/idx.php	Intel::URL	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        simpsons.freesexycomics.com/wp06/wp-includes/po.php	Intel::URL	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        topstonet.ru/modules/mod_search/source.php	Intel::URL	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        zhayvoronok.com/wp-includes/pomo/idx.php	Intel::URL	CERT	https://yeti.host.tld/XXXX-YYY	T	-	-
        
        $ stixtransclient.py -b --config ~/src/cti-toolkit/config/ctitoolkit.conf.sample-hailataxii \
                             --begin-timestamp `date +%Y-%m-%dT00:00:00.000000+00:00`
    
        http://ebay.x10host.com/ws/NeBayISAPI.dl/oo_login.php	Intel::URL	HAT	hailataxii.com	T	-	-
        http://golden-corner.com/make/bookmark/ii.php?rand.13InboxLight.aspxn.1774256418=	Intel::URL	HAT	hailataxii.com	T	-	-
        http://redbankplainsvet.com/324432423/192317148/	Intel::URL	HAT	hailataxii.com	T	-	-
        http://www.gallecarhire.com/Admin/k/isx007/gdd.htm	Intel::URL	HAT	hailataxii.com	T	-	-
        http://www.ibankservice-us.com/e49b438be1a419630a52f4792726351a/	Intel::URL	HAT	hailataxii.com	T	-	-
        http://www.kaliluana.com/wp-includes/images/media/view/secure-dropbox/document/	Intel::URL	HAT	hailataxii.com	T	-	-
        http://www.myownboss.co.zw/ab/ggdc/	Intel::URL	HAT	hailataxii.com	T	-	-
        http://www.performance2.co.uk/wp-content/senn/	Intel::URL	HAT	hailataxii.com	T	-	-
        http://www.toldosuniao.com.br/wp-admin/user/wp-config/user/config.inc/	Intel::URL	HAT	hailataxii.com	T	-	-

:mod:`stixtransclient.py` help
------------------------------

The command line (and configuration) options for stixtransclient.py are
displayed below::

    $ stixtransclient.py -h

usage: stixtransclient.py [-h] [-a] [-c] [-n] [-v] [-d] [-b] [--bro_no_notice]
                          [--misp] [-t] [-f FIELD_SEPARATOR] [-s]
                          [--base_url BASE_URL] [--source SOURCE] [--header]
                          [--config CONFIG] [--hostname HOSTNAME]
                          [--username USERNAME] [--password PASSWORD]
                          [--key KEY] [--cert CERT] [--soltra] [--ssl]
                          [--path PATH] [--collection COLLECTION]
                          [--begin-timestamp BEGIN_TS]
                          [--end-timestamp END_TS]
                          [--subscription-id SUBSCRIPTION_ID]
                          [--misp_url MISP_URL] [--misp_key MISP_KEY]
                          [--misp_distribution MISP_DISTRIBUTION]
                          [--misp_threat MISP_THREAT]
                          [--misp_analysis MISP_ANALYSIS]
                          [--misp_info MISP_INFO] [--misp_published]
                          [--file FILE | --taxii]

Utility to extract observables from local STIX files or a TAXII server Args
that start with '--' (eg. --aus) can also be set in a config file
(/etc/ctitoolkit.conf or ~/.ctitoolkit or specified via --config) by using
.ini or .yaml-style syntax (eg. aus=value). If an arg is specified in more
than one place, then command-line values override config file values which
override defaults.

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG       Configuration file to use
  --file FILE           Full path to XML file to process
  --taxii               TAXII server and arguments for poll client

input:
  -a, --aus             input is CERT Australia formatted STIX
  -c, --ca              input is CCIRC formatted STIX
  -n, --nccic           input is NCCIC formatted STIX

output:
  -v, --verbose         verbose output
  -d, --debug           Enable debug output
  -b, --bro             output bro intel framework formatted text
  --bro_no_notice       Suppress bro intel notice framework messages
  --misp                Feed output to MISP
  -t, --text            output delimited text
  -f FIELD_SEPARATOR    Field separation character to use
  -s, --stats           display summary stats
  --base_url BASE_URL   Base URL for indicator source - used in bro and MISP
                        output
  --source SOURCE       Source of indicators - eg Hailataxii, CERT-AU
  --header              Include header row for text output

taxii:
  --hostname HOSTNAME   Hostname of TAXII server. Defaults to taxii.host.tld
  --username USERNAME   Username for TAXII authentication
  --password PASSWORD   Password for TAXII authentication. Default value:
                        guest
  --key KEY             PEM Key for TAXII authentication
  --cert CERT           PEM Certiificate file for authenticating to TAXII
  --soltra              TAXII server is a SoltraEdge appliance
  --ssl                 Use SSL to connect to TAXII server
  --path PATH           Path on TAXII server. Defaults to /services/poll/
  --collection COLLECTION
                        Data Collection to poll. Defaults to 'default'.
  --begin-timestamp BEGIN_TS
                        The begin timestamp (format: YYYY-MM-
                        DDTHH:MM:SS.ssssss+/-hh:mm) for the poll request.
                        Defaults to None.
  --end-timestamp END_TS
                        The end timestamp (format: YYYY-MM-
                        DDTHH:MM:SS.ssssss+/-hh:mm) for the poll request.
                        Defaults to None.
  --subscription-id SUBSCRIPTION_ID
                        The Subscription ID for the poll request. Defaults to
                        None.

misp:
  --misp_url MISP_URL   URL of MISP server. Defaults to misp.host.tld
  --misp_key MISP_KEY   Token for accessing MISP instance
  --misp_distribution MISP_DISTRIBUTION
                        Distribution group in MISP. Defaults to Your
                        organisation only (0)
  --misp_threat MISP_THREAT
                        Threat level in MISP. Defaults to undefined (4)
  --misp_analysis MISP_ANALYSIS
                        Analysis phase in MISP. Defaults to initial (0)
  --misp_info MISP_INFO
                        MISP event description. Defaults to STIX package title
                        or Automated STIX ingest
  --misp_published      Set MISP published state to True
