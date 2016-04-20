"""TAXII transform MISP tests.

The STIX transform module can publish results to a MISP server.
"""
import httpretty
import json
import mock
import StringIO

import certau.transform
import stix.core


@httpretty.activate
@mock.patch('certau.transform.misp.time.sleep')
def test_misp_publishing(_):
    """Test that the stixtrans module can submit to a MISP server."""
    # STIX file to test against. Place in a StringIO instance so we can
    # close the file.
    with open('tests/CA-TEST-STIX.xml', 'rb') as stix_f:
        stix_io = StringIO.StringIO(stix_f.read())

    # Create a transformer - select 'text' output format and flag MISP
    # publishing (with appropriate settings).
    package = stix.core.STIXPackage.from_xml(stix_io)
    misp_args = {
        'misp_url': 'http://misp.host.tld/',
        'misp_key': '111111111111111111111111111',
    }
    misp_event_args = {
        'distribution': 1,
        'threat_level': 4,
        'analysis': 0,
    }

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
            'distribution': misp_event_args['distribution'],
        }}),
        content_type='application/json',
    )

    # Mock the adding of a tag to an event
    httpretty.register_uri(
        httpretty.POST,
        'http://misp.host.tld/events/addTag',
        body=json.dumps({'Event': {
            'id': '0',
            'tag': 4,
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
    misp = certau.transform.StixMispTransform.get_misp_object(
        **misp_args
    )
    transformer = certau.transform.StixMispTransform(
        package=package,
        misp=misp,
        **misp_event_args
    )
    transformer.publish()

    # Test the correct requests were made
    reqs = list(httpretty.httpretty.latest_requests)

    # The "get version" request includes the MISP key.
    r_get_version = reqs[0]
    assert r_get_version.path == '/servers/getVersion'
    assert r_get_version.headers.dict['authorization'] == misp_args['misp_key']

    # The event creation request includes basic information.
    r_create_event = reqs[1]
    assert r_create_event.path == '/events'
    assert json.loads(r_create_event.body) == {
        u'Event': {
            u'analysis': misp_event_args['analysis'],
            u'published': False,
            u'threat_level_id': misp_event_args['threat_level'],
            u'distribution': misp_event_args['distribution'],
            u'date': '2015-12-23',
            u'info': 'CA-TEST-STIX | Test STIX data'
        }
    }

    # The TLP tag is added to the event.
    r_add_tag = reqs[2]
    assert r_add_tag.path == '/events/addTag'
    assert json.loads(r_add_tag.body) == {
        u'request': {
            u'Event': {
                u'id': '0',
                u'tag': 4,
            }
        }
    }

    # The event is then updated with the observables, over multiple
    # requests. We're only interested in the 'Attribute' key here as that
    # contains the data extracted from the observable.
    obs_attributes = sorted([json.loads(request.body)['Event']['Attribute'][0]
                             for request
                             in reqs[3:]])

    assert obs_attributes == sorted([
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'11111111111111112977fa0588bd504a',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'ccccccccccccccc33574c79829dc1ccf',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'11111111111111133574c79829dc1ccf',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'11111111111111111f2601b4d21660fb',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'1111111111b42b57f518197d930471d9',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'mutex',
            u'value': u'\\BaseNamedObjects\\MUTEX_0001',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'mutex',
            u'value': u'\\BaseNamedObjects\\WIN_ABCDEF',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'mutex',
            u'value': u'\\BaseNamedObjects\\iurlkjashdk',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'regkey|value',
            u'value': u'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|hotkey\\%APPDATA%\\malware.exe -st',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'sha1',
            u'value': u'893fb19ac24eabf9b1fe1ddd1111111111111111',
        },
        {
            u'category': u'Artifacts dropped',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'sha256',
            u'value': u'11111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf',
        },
        {
            u'category': u'Network activity',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'domain',
            u'value': u'bad.domain.org',
        },
        {
            u'category': u'Network activity',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'domain',
            u'value': u'dnsupdate.dyn.net',
        },
        {
            u'category': u'Network activity',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'domain',
            u'value': u'free.stuff.com',
        },
        {
            u'category': u'Network activity',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'ip-dst',
            u'value': u'183.82.180.95',
        },

        {
            u'category': u'Network activity',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'ip-dst',
            u'value': u'111.222.33.44',
        },
        {
            u'category': u'Network activity',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'ip-dst',
            u'value': u'158.164.39.51',
        },
        {
            u'category': u'Network activity',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'url',
            u'value': u'http://host.domain.tld/path/file',
        },
        {
            u'category': u'Network activity',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'user-agent',
            u'value': u'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36',
        },
        {
            u'category': u'Payload delivery',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'email-src',
            u'value': u'sender@domain.tld',
        },
        {
            u'category': u'Payload delivery',
            u'distribution': 1,
            u'to_ids': True,
            u'type': u'email-subject',
            u'value': u'Important project details',
        },
    ])
