"""TAXII transform MISP tests.

The STIX transform module can publish results to a MISP server.
"""
import httpretty
import json
import mock
import StringIO
import pytest

import certau.transform
import stix.core


@httpretty.activate
@mock.patch('certau.transform.misp.time.sleep')
@pytest.mark.parametrize("stix_version", [111, 12])
def test_misp_publishing(_,stix_version):
    """Test that the stixtrans module can submit to a MISP server."""
    # STIX file to test against. Place in a StringIO instance so we can
    # close the file.
    with open(('TEST-STIX-1.2.xml' if stix_version == 12 else 'TEST-STIX-1.1.1.xml'), 'rb') as stix_f:
        stix_io = StringIO.StringIO(stix_f.read())

    # Create a transformer - select 'text' output format and flag MISP
    # publishing (with appropriate settings).
    package = stix.core.STIXPackage.from_xml(stix_io)
    misp_args = {
        'misp_url': 'http://misp.host.tld/',
        'misp_key': '111111111111111111111111111',
    }
    misp_event_args = {
        'distribution': u'1',
        'threat_level': u'4',
        'analysis': u'0',
    }

    # Ensures that non-registered paths fail
    httpretty.HTTPretty.allow_net_connect = False

    # Mock the PyMISP version retrieval
    httpretty.register_uri(
        httpretty.GET,
        'http://misp.host.tld/servers/getPyMISPVersion.json',
        body=json.dumps({
            'version': '2.4.71',
        }),
        content_type='application/json',
    )

    # Mock the retrieval of tags
    httpretty.register_uri(
        httpretty.GET,
        'http://misp.host.tld/tags',
        body=json.dumps({'Tag': [{
            'id': '1',
            'name': 'tlp:white',
        }]}),
        content_type='application/json',
    )

    # Mock the creation of an event
    httpretty.register_uri(
        httpretty.POST,
        'http://misp.host.tld/events',
        body=json.dumps({'Event': {
            'id': '0',
            'uuid': '590980a2-154c-47fb-b494-26660a00020f',
            'info': 'CA-TEST-STIX | Test STIX data',
            'distribution': misp_event_args['distribution'],
        }}),
        content_type='application/json',
    )

    # Mock the adding of a tag to an event
    httpretty.register_uri(
        httpretty.POST,
        'http://misp.host.tld/tags/attachTagToObject',
        body=json.dumps({}),
        content_type='application/json',
    )

    # Mock adding an attribute to a event 0.
    httpretty.register_uri(
        httpretty.POST,
        'http://misp.host.tld/attributes/add/0',
        body=json.dumps({}),
        content_type='application/json',
    )

    # Perform the processing and the misp publishing, ie make the HTTP requests
    # to which httpretty will respond
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
    assert r_get_version.path == '/servers/getPyMISPVersion.json'
    assert r_get_version.headers.dict['authorization'] == misp_args['misp_key']

    # The event creation request includes basic information.
    #TODO - change assertion so that it complies with the schema appropriate to the stix_version
    r_create_event = reqs[2]
    assert r_create_event.path == '/events'
    assert json.loads(r_create_event.body) == {
        u'Event': {
            u'Tag': [],
            u'attributes': [],
            u'analysis': misp_event_args['analysis'],
            u'published': False,
            u'threat_level_id': misp_event_args['threat_level'],
            u'distribution': misp_event_args['distribution'],
            u'date': u'2015-12-23',
            u'info': u'CA-TEST-STIX | Test STIX data'
        }
    }

    # The TLP tag is added to the event.
    r_add_tag = reqs[4]
    assert r_add_tag.path == '/tags/attachTagToObject'
    assert json.loads(r_add_tag.body) == {
        u'uuid': '590980a2-154c-47fb-b494-26660a00020f',
        u'tag': '1',
    }

    # The event is then updated with the observables, over multiple
    # requests. We're only interested in the 'Attribute' key here as that
    # contains the data extracted from the observable.
    obs_attributes = sorted([json.loads(request.body)
                             for request
                             in reqs[5:]])

"""
        for (attr, test_attr,) in zip(obs_attributes, test_obs_attributes):
>           assert attr == test_attr
E           AssertionError: assert {'category': ...': 'md5', ...} == {'category': '...on': '5', ...}
E             Common items:
E             {u'category': u'Artifacts dropped',
E              u'disable_correlation': False,
E              u'to_ids': True,
E              u'type': u'md5',
E              u'value': u'11111111111111111f2601b4d21660fb'}
E             Right contains more items:
E             {u'comment': u'', u'distribution': '5'}
E             Full diff:
E             {u'category': u'Artifacts dropped',
E             +  u'comment': u'',
E             u'disable_correlation': False,
E             +  u'distribution': '5',
E             u'to_ids': True,
E             u'type': u'md5',
E             u'value': u'11111111111111111f2601b4d21660fb'}

"""

    test_obs_attributes = sorted([
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'11111111111111112977fa0588bd504a',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'ccccccccccccccc33574c79829dc1ccf',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'11111111111111133574c79829dc1ccf',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'11111111111111111f2601b4d21660fb',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'1111111111b42b57f518197d930471d9',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'mutex',
            u'value': u'\\BaseNamedObjects\\MUTEX_0001',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'mutex',
            u'value': u'\\BaseNamedObjects\\WIN_ABCDEF',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'mutex',
            u'value': u'\\BaseNamedObjects\\iurlkjashdk',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'regkey|value',
            u'value': u'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|hotkey\\%APPDATA%\\malware.exe -st',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'sha1',
            u'value': u'893fb19ac24eabf9b1fe1ddd1111111111111111',
        },
        {
            u'category': u'Artifacts dropped',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'sha256',
            u'value': u'11111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf',
        },
        {
            u'category': u'Network activity',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'domain',
            u'value': u'bad.domain.org',
        },
        {
            u'category': u'Network activity',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'domain',
            u'value': u'dnsupdate.dyn.net',
        },
        {
            u'category': u'Network activity',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'domain',
            u'value': u'free.stuff.com',
        },
        {
            u'category': u'Network activity',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'ip-dst',
            u'value': u'183.82.180.95',
        },

        {
            u'category': u'Network activity',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'ip-dst',
            u'value': u'111.222.33.44',
        },
        {
            u'category': u'Network activity',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'ip-dst',
            u'value': u'158.164.39.51',
        },
        {
            u'category': u'Network activity',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'url',
            u'value': u'http://host.domain.tld/path/file',
        },
        {
            u'category': u'Network activity',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'user-agent',
            u'value': u'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36',
        },
        {
            u'category': u'Payload delivery',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'email-src',
            u'value': u'sender@domain.tld',
        },
        {
            u'category': u'Payload delivery',
            u'comment': u'',
            u'disable_correlation': False,
            u'distribution': '5',
            u'to_ids': True,
            u'type': u'email-subject',
            u'value': u'Important project details',
        },
    ])

    for (attr, test_attr,) in zip(obs_attributes, test_obs_attributes):
        assert attr == test_attr
