""" Transform tests.
"""
import StringIO
import textwrap

import options_mock
import certau.transform


class TestTransforms(object):
    """ Basic high-level tests of the transform functionality.
    """
    def test_transform_to_text(self, capsys):
        """ Test of transform between a sample STIX file and the 'text' output
            format.
        """
        # Place in a StringIO instance so we can close the file.
        with open('tests/CA-TEST-STIX.xml', 'rb') as stix_f:
            stix_io = StringIO.StringIO(stix_f.read())

        # Select 'text' output format.
        options = options_mock.TransformOptions({'text': True, 'header': True})

        transformer = certau.transform.StixTransform(options)
        transformer.process_input(stix_io)

        # The transformer prints to standard output so we capture that.
        stdout = capsys.readouterr()[0].strip()

        assert stdout == textwrap.dedent("""
            id|url|url_condition|
            =====================
            cert_au:Observable-1a919136-ba69-4a28-9615-ad6ee37e88a5|http://host.domain.tld/path/file|None|

            id|fromaddr|fromaddr_condition|toaddr|toaddr_condition|subject|subject_condition|attachment_refs|
            =================================================================================================
            cert_au:Observable-b6770e76-7f05-48cb-a3de-7ba5fece8751|sender@domain.tld|Equals|None|None|None|None|[]|
            cert_au:Observable-31e5af27-2f71-4922-b49c-cfd3ddee2963|None|None|None|None|Important project details|Equals|['cert_au:Observable-5d647351-f8cf-442f-9e5a-ba6967c16301']|

            id|file_name|file_name_condition|hash_type|hashes|
            ==================================================
            cert_au:Observable-5d647351-f8cf-442f-9e5a-ba6967cccccc|filenameonly.doc|None|||
            cert_au:Observable-5d647351-f8cf-442f-9e5a-ba6967c16301|project.doc|Equals|MD5|1111111111b42b57f518197d930471d9|
            cert_au:Observable-cccccd51-a524-483f-8f17-2e8ff8474d80|None|None|MD5|cccccccccccccc33574c79829dc1ccf|
            cert_au:Observable-84060d51-a524-483f-8f17-2e8ff8474d80|Execute_this.jar|Equals|MD5|11111111111111133574c79829dc1ccf|
            cert_au:Observable-3ad6c684-80aa-4d92-9fef-7a9f70ccba95|malware.exe|Equals|MD5|11111111111f2601b4d21660fb|
            cert_au:Observable-7cb2ac9f-4cae-443f-905d-0b01cb1faedc|VPN.exe|Equals|SHA256|111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf|
            cert_au:Observable-7cb2ac9f-4cae-443f-905d-0b01cb1faedc|VPN.exe|Equals|SHA1|893fb19ac24eabf9b1fe1ddd1111111111111111|
            cert_au:Observable-7cb2ac9f-4cae-443f-905d-0b01cb1faedc|VPN.exe|Equals|MD5|11111111111111112977fa0588bd504a|

            id|hive|hive_condition|key|key_condition|name|name_condition|data|data_condition|
            =================================================================================
            cert_au:Observable-d0f4708e-4f2b-49c9-bc31-29e7119844e5|HKEY_CURRENT_USER\\Software|Equals|\\Microsoft\\Windows\\CurrentVersion\\Run|Equals|hotkey|Equals|%APPDATA%\\malware.exe -st|Equals|

            id|domain|domain_condition|
            ===========================
            cert_au:Observable-6517027e-2cdb-47e8-b5c8-50c6044e42de|bad.domain.org|None|
            cert_au:Observable-c97cc016-24b6-4d02-afc2-308742c722dc|dnsupdate.dyn.net|None|
            cert_au:Observable-138a5be6-56b2-4d2d-af73-2d4865d6ff71|free.stuff.com|None|

            id|category|address|
            ====================
            cert_au:Observable-fe5ddeac-f9b0-4488-9f89-bfbd9351efd4|ipv4-addr|158.164.39.51|
            cert_au:Observable-ccccceac-f9b0-4488-9f89-bfbd9351efd4|ipv4-addr|111.222.33.44|
            CCIRC-CCRIC:Observable-01234567-2823-4d6d-8d77-bae10ca5bd97|ipv4-addr|183.82.180.95|

            id|mutex|condition|
            ===================
            NCCIC:Observable-01234567-6868-4ffd-babc-ba2ad0e34f43|WIN_ABCDEF|None|
            NCCIC:Observable-abcdef01-3363-4533-a77c-10d71c371282|MUTEX_0001|None|
            CCIRC-CCRIC:Observable-01234567-e44c-473a-85c6-fc6c2e781114|iurlkjashdk|Equals|

            id|user_agent|user_agent_condition|
            ===================================
            cert_au:Observable-6a733d83-5d19-4d17-a51f-5bcb4ebc860a|Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36|None|
        """).strip()

    def test_transform_to_stats(self, capsys):
        """ Test of transform between a sample STIX file and the 'stats'
            output format.
        """
        # Place in a StringIO instance so we can close the file.
        with open('tests/CA-TEST-STIX.xml', 'rb') as stix_f:
            stix_io = StringIO.StringIO(stix_f.read())

        # Select 'stats' output format.
        options = options_mock.TransformOptions({'stats': True, 'title': 'Testing title'})

        transformer = certau.transform.StixTransform(options)
        transformer.process_input(stix_io)

        # The transformer prints to standard output so we capture that,
        # stripping any leading/trailing white space.
        stdout = capsys.readouterr()[0].strip()

        assert stdout == textwrap.dedent("""
            ++++++++++++++++++++++++++++++++++++++++++
            Summary statistics:\tTesting title(WHITE)
            ++++++++++++++++++++++++++++++++++++++++++
            Address      related observables: \t3
            Domain       related observables: \t3
            Email        related observables: \t2
            File         related observables: \t6
            Mutex        related observables: \t3
            User-Agent   related observables: \t1
            URL          related observables: \t1
            WinRegkey    related observables: \t1
            ++++++++++++++++++++++++++++++++++++++++++
        """).strip()

    def test_transform_to_bro(self, capsys):
        """ Test of transform between a sample STIX file and the 'bro' output
            format.
        """
        # Place in a StringIO instance so we can close the file.
        with open('tests/CA-TEST-STIX.xml', 'rb') as stix_f:
            stix_io = StringIO.StringIO(stix_f.read())

        # Select 'bro' output format.
        options = options_mock.TransformOptions({'bro': True, 'aus': True})

        transformer = certau.transform.StixTransform(options)
        transformer.process_input(stix_io)

        # The transformer prints to standard output so we capture that.
        stdout = capsys.readouterr()[0].strip()

        assert stdout == textwrap.dedent("""
            host.domain.tld/path/file\tIntel::URL\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            sender@domain.tld\tIntel::EMAIL\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            1111111111b42b57f518197d930471d9\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            cccccccccccccc33574c79829dc1ccf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            11111111111111133574c79829dc1ccf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            11111111111f2601b4d21660fb\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            893fb19ac24eabf9b1fe1ddd1111111111111111\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            11111111111111112977fa0588bd504a\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            bad.domain.org\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            dnsupdate.dyn.net\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            free.stuff.com\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            158.164.39.51\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            111.222.33.44\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            183.82.180.95\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
            Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36\tIntel::SOFTWARE\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tT\t-\t-
        """).strip()
        
        # Place in a StringIO instance so we can close the file.
        with open('tests/CA-TEST-STIX.xml', 'rb') as stix_f:
            stix_io = StringIO.StringIO(stix_f.read())

        # Select 'bro' output format and test no notice option.
        options = options_mock.TransformOptions({'bro': True, 'aus': True, 'bro_no_notice': True})

        transformer = certau.transform.StixTransform(options)
        transformer.process_input(stix_io)

        # The transformer prints to standard output so we capture that.
        stdout = capsys.readouterr()[0].strip()
        print("DEBUG: ", stdout)

        assert stdout == textwrap.dedent("""
            host.domain.tld/path/file\tIntel::URL\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            sender@domain.tld\tIntel::EMAIL\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            1111111111b42b57f518197d930471d9\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            cccccccccccccc33574c79829dc1ccf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            11111111111111133574c79829dc1ccf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            11111111111f2601b4d21660fb\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            893fb19ac24eabf9b1fe1ddd1111111111111111\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            11111111111111112977fa0588bd504a\tIntel::FILE_HASH\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            bad.domain.org\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            dnsupdate.dyn.net\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            free.stuff.com\tIntel::DOMAIN\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            158.164.39.51\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            111.222.33.44\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            183.82.180.95\tIntel::ADDR\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
            Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36\tIntel::SOFTWARE\tCERT-AU\thttps://www.cert.gov.au/TEST-STIX\tF\t-\t-
        """).strip()
