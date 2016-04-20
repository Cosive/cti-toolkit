""" TAXII transform MISP tests.

    The STIX transform module can publish results to a MISP server.
"""
import httpretty
import json
import mock
import StringIO

import options_mock
import certau.transform


class TestClient(object):
    """ Basic high-level tests of the transform functionality.
    """
    @httpretty.activate
    @mock.patch('certau.transform.stixtrans.time.sleep')
    def test_misp_publishing(self, _):
        """ Test that the stixtrans module can submit to a MISP server.
        """
        # STIX file to test against. Place in a StringIO instance so we can
        # close the file.
        with open('tests/CA-TEST-STIX.xml', 'rb') as stix_f:
            stix_io = StringIO.StringIO(stix_f.read())

        # Create a transformer - select 'text' output format and flag MISP
        # publishing (with appropriate settings).
        options = options_mock.TransformOptions({
            'text': True,
            'misp': True,
            'misp_url': 'http://misp.host.tld/',
            'misp_key': '111111111111111111111111111',
            'misp_distribution': 1,
            'misp_threat': 4,
            'misp_analysis': 0,
        })
        transformer = certau.transform.StixTransform(options)

        # Ensures that non-registered paths fail
        httpretty.HTTPretty.allow_net_connect = False

        # Mock the MISP version retrieval.
        httpretty.register_uri(
            httpretty.GET,
            'http://misp.host.tld/servers/getVersion',
            body=json.dumps({}),
            content_type='application/json',
        )

        # Mock the creation of an event
        httpretty.register_uri(
            httpretty.POST,
            'http://misp.host.tld/events',
            body=json.dumps({'Event': {
                'id': '0',
                'distribution': options.misp_distribution,
            }}),
            content_type='application/json',
        )

        # Mock editing of a created event.
        httpretty.register_uri(
            httpretty.POST,
            'http://misp.host.tld/events/0',
            body=json.dumps({}),
            content_type='application/json',
        )

        # Perform the processing and the misp publishing.
        transformer.process_input(stix_io)

        # Test the correct requests were made
        reqs = list(httpretty.httpretty.latest_requests)

        # The "get version" request includes the MISP key.
        r_get_version = reqs[0]
        assert r_get_version.path == '/servers/getVersion'
        assert r_get_version.headers.dict['authorization'] == options.misp_key

        # The event creation request includes basic information.
        r_create_event = reqs[1]
        assert r_create_event.path == '/events'
        assert json.loads(r_create_event.body) == {
            'Event': {
                'analysis': options.misp_analysis,
                'published': False,
                'threat_level_id': options.misp_threat,
                'distribution': options.misp_distribution,
                'date': '2015-12-23',
                'info': 'unknown:CA-TEST-STIX | Test STIX data'
            }
        }

        # The event is then updated with the observables, over multiple
        # requests. We're only interested in the 'Attribute' key here as that
        # contains the data extracted from the observable.
        obs_attributes = sorted([json.loads(request.body)['Event']['Attribute'][0]
                                 for request
                                 in reqs[2:]])

        assert obs_attributes == sorted([
            {
                'category': 'Artifacts dropped',
                'distribution': 1,
                'to_ids': True,
                'type': 'md5',
                'value': '11111111111111112977fa0588bd504a',
            },
            {
                'category': 'Artifacts dropped',
                'distribution': 1,
                'to_ids': True,
                'type': 'md5',
                'value': 'cccccccccccccc33574c79829dc1ccf',
            },
            {
                'category': 'Artifacts dropped',
                'distribution': 1,
                'to_ids': True,
                'type': 'md5',
                'value': '11111111111111133574c79829dc1ccf',
            },
            {
                'category': 'Artifacts dropped',
                'distribution': 1,
                'to_ids': True,
                'type': 'md5',
                'value': '11111111111f2601b4d21660fb',
            },
            {
                'category': 'Artifacts dropped',
                'distribution': 1,
                'to_ids': True,
                'type': 'md5',
                'value': '1111111111b42b57f518197d930471d9',
            },
            {
                'category': 'Artifacts dropped',
                'distribution': 1,
                'to_ids': True,
                'type': 'regkey|value',
                'value': 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|hotkey\\%APPDATA%\\malware.exe -st',
            },
            {
                'category': 'Artifacts dropped',
                'distribution': 1,
                'to_ids': True,
                'type': 'sha1',
                'value': '893fb19ac24eabf9b1fe1ddd1111111111111111',
            },
            {
                'category': 'Artifacts dropped',
                'distribution': 1,
                'to_ids': True,
                'type': 'sha256',
                'value': '111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf',
            },
            {
                'category': 'Network activity',
                'distribution': 1,
                'to_ids': True,
                'type': 'domain',
                'value': 'bad.domain.org',
            },
            {
                'category': 'Network activity',
                'distribution': 1,
                'to_ids': True,
                'type': 'domain',
                'value': 'dnsupdate.dyn.net',
            },
            {
                'category': 'Network activity',
                'distribution': 1,
                'to_ids': True,
                'type': 'domain',
                'value': 'free.stuff.com',
            },
            {
                'category': 'Network activity',
                'distribution': 1,
                'to_ids': True,
                'type': 'ip-dst',
                'value': '183.82.180.95',
            },

            {
                'category': 'Network activity',
                'distribution': 1,
                'to_ids': True,
                'type': 'ip-dst',
                'value': '111.222.33.44',
            },
            {
                'category': 'Network activity',
                'distribution': 1,
                'to_ids': True,
                'type': 'ip-dst',
                'value': '158.164.39.51',
            },
            {
                'category': 'Network activity',
                'distribution': 1,
                'to_ids': True,
                'type': 'url',
                'value': 'http://host.domain.tld/path/file',
            },
            {
                'category': 'Network activity',
                'distribution': 1,
                'to_ids': True,
                'type': 'user-agent',
                'value': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36',
            },
            {
                'category': 'Payload delivery',
                'distribution': 1,
                'to_ids': True,
                'type': 'email-src',
                'value': 'sender@domain.tld',
            },
            {
                'category': 'Payload delivery',
                'distribution': 1,
                'to_ids': True,
                'type': 'email-subject',
                'value': 'Important project details',
            },
        ])
