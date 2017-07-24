.. _about:

About the CTI-Toolkit
=====================

Few systems can utilise indicators and observables when stored in STIX packages.
CERT Australia has developed a utility (``stixtransclient.py``) that allows the
atomic observables contained within a STIX package to be extracted and presented
in either a text delimited format, in the `Bro Intel Framework
<http://blog.bro.org/2014/01/intelligence-data-and-bro_4980.html>`_ format, or in
a `Snort
<https://snort.org/>`_ or `Suricata
<https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata>`_ rule format .
The utility can also communicate with a `MISP
<http://www.misp-project.org/>`_ server and insert observables from a STIX
package into a new MISP event.
