# -*- coding: utf-8 -*-
"""Basic high-level tests of the transform functionality."""
import csv
import StringIO
import textwrap
import pytest

import certau.transform

@pytest.mark.parametrize("stix_version", [111, 12])
def test_transform_to_text(stix_version, package_111, package_12):
    """Test of transform between a sample STIX file and the 'text' output
    format.
    """
    # Select the right package for the stix version
    package = package_12 if stix_version == 12 else package_111    

    # Select 'text' output format transformer
    transformer = certau.transform.StixCsvTransform(
        package, include_header=True
    )

    assert transformer.text().strip() == textwrap.dedent("""
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
        cert_au:Observable-84060d51-a524-483f-8f17-2e8ff8474d80|Execute—this.jar|Equals|MD5|11111111111111133574c79829dc1ccf
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
        cert_au:Observable-d0f4708e-4f2b-49c9-bc31-29e7119844e5|HKEY_CURRENT_USER\\Software|Equals|\\Microsoft\\Windows\\CurrentVersion\\Run|Equals|hotkey|Equals|%APPDATA%\\malware.exe -st|Equals
    """).strip()

@pytest.mark.parametrize("stix_version", [111, 12])
def test_text_delimiter_quoting(stix_version, package_111, package_12):
    """Test that delimiters included in the values of text transforms are
    correctly quoted.
    """
    # Select the right package for the stix version
    package = package_12 if stix_version == 12 else package_111    

    transformer = certau.transform.StixCsvTransform(package)

    joined = transformer.join(('first|second', 'third'))
    assert joined == '"first|second"|third'

    # This quoting is compatible with csv.reader.
    reader = csv.reader(StringIO.StringIO(joined), delimiter='|')

    assert reader.next() == ['first|second', 'third']

@pytest.mark.parametrize("stix_version", [111, 12])
def test_transform_to_stats(stix_version, package_111, package_12):
    """Test of transform between a sample STIX file and the 'stats'
    output format.
    """
    # Select the right package for the stix version
    package = package_12 if stix_version == 12 else package_111    

    # Select 'stats' output format.
    transformer = certau.transform.StixStatsTransform(
        package, include_header=True
    )

    assert transformer.text().strip() == textwrap.dedent("""
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
    """).strip()

@pytest.mark.parametrize("stix_version", [111, 12])
def test_transform_to_bro(stix_version, package_111, package_12):
    """Test of transform between a sample STIX file and the 'bro' output
    format.
    """
    # Select the right package for the stix version
    package = package_12 if stix_version == 12 else package_111    

    # Select 'stats' output format.
    transformer = certau.transform.StixBroIntelTransform(
        package, include_header=True
    )

    assert transformer.text().strip().expandtabs() == textwrap.dedent("""
        # indicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\tmeta.if_in\tmeta.whitelist
        158.164.39.51\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        111.222.33.44\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        bad.domain.org\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        dnsupdate.dyn.net\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        free.stuff.com\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        sender@domain.tld\tIntel::EMAIL\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        1111111111b42b57f518197d930471d9\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        ccccccccccccccc33574c79829dc1ccf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        11111111111111133574c79829dc1ccf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        11111111111111111f2601b4d21660fb\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        11111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        893fb19ac24eabf9b1fe1ddd1111111111111111\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        11111111111111112977fa0588bd504a\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36\tIntel::SOFTWARE\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
        183.82.180.95\tIntel::ADDR\tCCIRC\thttps://www.publicsafety.gc.ca/cnt/ntnl-scrt/cbr-scrt/ccirc-ccric-eng.aspx\tT\t-\t-
        host.domain.tld/path/file\tIntel::URL\tCERT-AU\thttps://www.cert.gov.au/\tT\t-\t-
    """).strip().expandtabs()

    # Select 'bro' output format and test no notice option.
    transformer = certau.transform.StixBroIntelTransform(
        package, do_notice='F'
    )

    assert transformer.text().strip().expandtabs() == textwrap.dedent("""
        158.164.39.51\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        111.222.33.44\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        bad.domain.org\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        dnsupdate.dyn.net\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        free.stuff.com\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        sender@domain.tld\tIntel::EMAIL\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        1111111111b42b57f518197d930471d9\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        ccccccccccccccc33574c79829dc1ccf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        11111111111111133574c79829dc1ccf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        11111111111111111f2601b4d21660fb\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        11111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        893fb19ac24eabf9b1fe1ddd1111111111111111\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        11111111111111112977fa0588bd504a\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36\tIntel::SOFTWARE\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
        183.82.180.95\tIntel::ADDR\tCCIRC\thttps://www.publicsafety.gc.ca/cnt/ntnl-scrt/cbr-scrt/ccirc-ccric-eng.aspx\tF\t-\t-
        host.domain.tld/path/file\tIntel::URL\tCERT-AU\thttps://www.cert.gov.au/\tF\t-\t-
    """).strip().expandtabs()

@pytest.mark.parametrize("stix_version", [111, 12])
def test_transform_to_snort(stix_version, package_111, package_12):
    """Test of transform between a sample STIX file and the 'snort' output
    format.
    """
    # Select the right package for the stix version
    package = package_12 if stix_version == 12 else package_111    

    # Select 'stats' output format.
    transformer = certau.transform.StixSnortTransform(
            package, include_header=False
    )

    assert transformer.text().strip().expandtabs() == textwrap.dedent("""

        alert ip any any -> 158.164.39.51 any (flow:established,to_server; msg:"CTI-Toolkit connection to potentially malicious server 158.164.39.51 (ID cert_au:Observable-fe5ddeac-f9b0-4488-9f89-bfbd9351efd4)"; sid:5500000; rev:1; classtype:bad-unknown;)
        alert ip any any -> 111.222.33.44 any (flow:established,to_server; msg:"CTI-Toolkit connection to potentially malicious server 111.222.33.44 (ID cert_au:Observable-ccccceac-f9b0-4488-9f89-bfbd9351efd4)"; sid:5500001; rev:1; classtype:bad-unknown;)
        alert udp any any -> $EXTERNAL_NET 53 (byte_test:1, !&, 0xF8,2; content:"bad.domain.org"; fast_pattern:only; metadata:service dns; msg:"CTI-Toolkit connection to potentially malicious domain bad.domain.org (ID cert_au:Observable-6517027e-2cdb-47e8-b5c8-50c6044e42de)"; sid:5500002; rev:1; classtype:bad-unknown;)
        alert udp any any -> $EXTERNAL_NET 53 (byte_test:1, !&, 0xF8,2; content:"dnsupdate.dyn.net"; fast_pattern:only; metadata:service dns; msg:"CTI-Toolkit connection to potentially malicious domain dnsupdate.dyn.net (ID cert_au:Observable-c97cc016-24b6-4d02-afc2-308742c722dc)"; sid:5500003; rev:1; classtype:bad-unknown;)
        alert udp any any -> $EXTERNAL_NET 53 (byte_test:1, !&, 0xF8,2; content:"free.stuff.com"; fast_pattern:only; metadata:service dns; msg:"CTI-Toolkit connection to potentially malicious domain free.stuff.com (ID cert_au:Observable-138a5be6-56b2-4d2d-af73-2d4865d6ff71)"; sid:5500004; rev:1; classtype:bad-unknown;)
        alert ip any any -> 183.82.180.95 any (flow:established,to_server; msg:"CTI-Toolkit connection to potentially malicious server 183.82.180.95 (ID CCIRC-CCRIC:Observable-01234567-2823-4d6d-8d77-bae10ca5bd97)"; sid:5500005; rev:1; classtype:bad-unknown;)
        alert tcp any any -> $EXTERNAL_NET $HTTP_PORTS (flow:established,to_server; content:"host.domain.tld"; http_header; nocase; uricontent:"/path/file"; metadata:service http; msg:"CTI-Toolkit connection to potentially malicious url http://host.domain.tld/path/file (ID cert_au:Observable-1a919136-ba69-4a28-9615-ad6ee37e88a5)"; sid:5500006; rev:1; classtype:bad-unknown;)
    """).strip().expandtabs()
