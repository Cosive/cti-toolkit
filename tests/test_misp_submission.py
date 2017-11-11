"""TAXII transform MISP tests.

The STIX transform module can publish results to a MISP server.
"""
import httpretty
import json
import mock
import StringIO
import pytest
import pymisp
import certau.transform
import stix.core

from random import randint


@httpretty.activate
@mock.patch('certau.transform.misp.time.sleep')
@pytest.mark.parametrize("stix_version", [111, 12])
def test_misp_publishing(_,stix_version):
    """Test that the stixtrans module can submit to a MISP server."""

    def _create_response_content(fields={}):
        """Combine supplied dynamic fields with the static ones to emulate a MISP add attributes response"""
        static_fields = {
            u"id": randint(1,100),
            u"event_id": 1,
            u"object_id": 0,
            u"object_relation": None,
            u"to_ids": True,
            u"uuid": u"5a04f0cb-2244-4217-9a7e-0751c0a8c034",
            u"timestamp": u"1510273227",
            u"distribution": 0,
            u"sharing_group_id": 0,
            u"comment": u"",
            u"deleted": False,
        }
        static_fields.update(fields)
        return static_fields 

    def attribute_request_callback(request, uri, headers):
        response_fields = json.loads(request.body)
        body_content = json.dumps(_create_response_content(response_fields))
        return (200, headers, body_content)
        

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
        'distribution': u'0',
        'threat_level': u'4',
        'analysis': u'0',
    }

    # Ensures that non-registered paths fail
    httpretty.HTTPretty.allow_net_connect = False

    # Mock the PyMISP version retrieval from /servers/getPyMISPVersion.json
    # (This is the first thing PyMISP does after authentication) 
    pymisp_version = '.'.join(pymisp.__version__.split('.',1))
    httpretty.register_uri(
        httpretty.GET,
        'http://misp.host.tld/servers/getPyMISPVersion.json',
        body=json.dumps({
            'version': pymisp_version,
        }),
        content_type='application/json',
    )

    # Mock the retrieval of Types from /attributes/describeTypes.json
    # (This is the first thing PyMISP does after authentication) 
    httpretty.register_uri(
        httpretty.GET,
        'http://misp.host.tld/attributes/describeTypes.json',
        body=json.dumps({"result":{
                    "sane_defaults":{
                        "md5":{"default_category":"Payload delivery","to_ids":1},
                        "sha1":{"default_category":"Payload delivery","to_ids":1},
                        "sha256":{"default_category":"Payload delivery","to_ids":1},
                        "filename":{"default_category":"Payload delivery","to_ids":1},
                        "pdb":{"default_category":"Artifacts dropped","to_ids":0},
                        "filename|md5":{"default_category":"Payload delivery","to_ids":1},
                        "filename|sha1":{"default_category":"Payload delivery","to_ids":1},
                        "filename|sha256":{"default_category":"Payload delivery","to_ids":1},
                        "ip-src":{"default_category":"Network activity","to_ids":1},
                        "ip-dst":{"default_category":"Network activity","to_ids":1},
                        "hostname":{"default_category":"Network activity","to_ids":1},
                        "domain":{"default_category":"Network activity","to_ids":1},
                        "domain|ip":{"default_category":"Network activity","to_ids":1},
                        "email-src":{"default_category":"Payload delivery","to_ids":1},
                        "email-dst":{"default_category":"Network activity","to_ids":1},
                        "email-subject":{"default_category":"Payload delivery","to_ids":0},
                        "email-attachment":{"default_category":"Payload delivery","to_ids":1},
                        "email-body":{"default_category":"Payload delivery","to_ids":0},
                        "float":{"default_category":"Other","to_ids":0},
                        "url":{"default_category":"External analysis","to_ids":1},
                        "http-method":{"default_category":"Network activity","to_ids":0},
                        "user-agent":{"default_category":"Network activity","to_ids":0},
                        "regkey":{"default_category":"Persistence mechanism","to_ids":1},
                        "regkey|value":{"default_category":"Persistence mechanism","to_ids":1},
                        "AS":{"default_category":"Network activity","to_ids":0},
                        "snort":{"default_category":"Network activity","to_ids":1},
                        "pattern-in-file":{"default_category":"Payload installation","to_ids":1},
                        "pattern-in-traffic":{"default_category":"Network activity","to_ids":1},
                        "pattern-in-memory":{"default_category":"Payload installation","to_ids":1},
                        "yara":{"default_category":"Payload installation","to_ids":1},
                        "sigma":{"default_category":"Payload installation","to_ids":1},
                        "cookie":{"default_category":"Network activity","to_ids":0},
                        "vulnerability":{"default_category":"External analysis","to_ids":0},
                        "attachment":{"default_category":"External analysis","to_ids":0},
                        "malware-sample":{"default_category":"Payload delivery",
                        "to_ids":1},"link":{"default_category":"External analysis","to_ids":0},
                        "comment":{"default_category":"Other","to_ids":0},
                        "text":{"default_category":"Other","to_ids":0},
                        "hex":{"default_category":"Other","to_ids":0},
                        "other":{"default_category":"Other","to_ids":0},
                        "named pipe":{"default_category":"Artifacts dropped","to_ids":0},
                        "mutex":{"default_category":"Artifacts dropped","to_ids":1},
                        "target-user":{"default_category":"Targeting data","to_ids":0},
                        "target-email":{"default_category":"Targeting data","to_ids":0},
                        "target-machine":{"default_category":"Targeting data","to_ids":0},
                        "target-org":{"default_category":"Targeting data","to_ids":0},
                        "target-location":{"default_category":"Targeting data","to_ids":0},
                        "target-external":{"default_category":"Targeting data","to_ids":0},
                        "btc":{"default_category":"Financial fraud","to_ids":1},
                        "iban":{"default_category":"Financial fraud","to_ids":1},
                        "bic":{"default_category":"Financial fraud","to_ids":1},
                        "bank-account-nr":{"default_category":"Financial fraud","to_ids":1},
                        "aba-rtn":{"default_category":"Financial fraud","to_ids":1},
                        "bin":{"default_category":"Financial fraud","to_ids":1},
                        "cc-number":{"default_category":"Financial fraud","to_ids":1},
                        "prtn":{"default_category":"Financial fraud","to_ids":1},
                        "phone-number":{"default_category":"Person","to_ids":0},
                        "threat-actor":{"default_category":"Attribution","to_ids":0},
                        "campaign-name":{"default_category":"Attribution","to_ids":0},
                        "campaign-id":{"default_category":"Attribution","to_ids":0},
                        "malware-type":{"default_category":"Payload delivery","to_ids":0},
                        "uri":{"default_category":"Network activity","to_ids":1},
                        "authentihash":{"default_category":"Payload delivery","to_ids":1},
                        "ssdeep":{"default_category":"Payload delivery","to_ids":1},
                        "imphash":{"default_category":"Payload delivery","to_ids":1},
                        "pehash":{"default_category":"Payload delivery","to_ids":1},
                        "impfuzzy":{"default_category":"Payload delivery","to_ids":1},
                        "sha224":{"default_category":"Payload delivery","to_ids":1},
                        "sha384":{"default_category":"Payload delivery","to_ids":1},
                        "sha512":{"default_category":"Payload delivery","to_ids":1},
                        "sha512\/224":{"default_category":"Payload delivery","to_ids":1},
                        "sha512\/256":{"default_category":"Payload delivery","to_ids":1},
                        "tlsh":{"default_category":"Payload delivery","to_ids":1},
                        "filename|authentihash":{"default_category":"Payload delivery","to_ids":1},
                        "filename|ssdeep":{"default_category":"Payload delivery","to_ids":1},
                        "filename|imphash":{"default_category":"Payload delivery","to_ids":1},
                        "filename|impfuzzy":{"default_category":"Payload delivery","to_ids":1},
                        "filename|pehash":{"default_category":"Payload delivery","to_ids":1},
                        "filename|sha224":{"default_category":"Payload delivery","to_ids":1},
                        "filename|sha384":{"default_category":"Payload delivery","to_ids":1},
                        "filename|sha512":{"default_category":"Payload delivery","to_ids":1},
                        "filename|sha512\/224":{"default_category":"Payload delivery","to_ids":1},
                        "filename|sha512\/256":{"default_category":"Payload delivery","to_ids":1},
                        "filename|tlsh":{"default_category":"Payload delivery","to_ids":1},
                        "windows-scheduled-task":{"default_category":"Artifacts dropped","to_ids":0},
                        "windows-service-name":{"default_category":"Artifacts dropped","to_ids":0},
                        "windows-service-displayname":{"default_category":"Artifacts dropped","to_ids":0},
                        "whois-registrant-email":{"default_category":"Attribution","to_ids":0},
                        "whois-registrant-phone":{"default_category":"Attribution","to_ids":0},
                        "whois-registrant-name":{"default_category":"Attribution","to_ids":0},
                        "whois-registrar":{"default_category":"Attribution","to_ids":0},
                        "whois-creation-date":{"default_category":"Attribution","to_ids":0},
                        "x509-fingerprint-sha1":{"default_category":"Network activity","to_ids":1},
                        "dns-soa-email":{"default_category":"Attribution","to_ids":0},
                        "size-in-bytes":{"default_category":"Other","to_ids":0},
                        "counter":{"default_category":"Other","to_ids":0},
                        "datetime":{"default_category":"Other","to_ids":0},
                        "cpe":{"default_category":"Other","to_ids":0},
                        "port":{"default_category":"Network activity","to_ids":0},
                        "ip-dst|port":{"default_category":"Network activity","to_ids":1},
                        "ip-src|port":{"default_category":"Network activity","to_ids":1},
                        "hostname|port":{"default_category":"Network activity","to_ids":1},
                        "email-dst-display-name":{"default_category":"Payload delivery","to_ids":0},
                        "email-src-display-name":{"default_category":"Payload delivery","to_ids":0},
                        "email-header":{"default_category":"Payload delivery","to_ids":0},
                        "email-reply-to":{"default_category":"Payload delivery","to_ids":0},
                        "email-x-mailer":{"default_category":"Payload delivery","to_ids":0},
                        "email-mime-boundary":{"default_category":"Payload delivery","to_ids":0},
                        "email-thread-index":{"default_category":"Payload delivery","to_ids":0},
                        "email-message-id":{"default_category":"Payload delivery","to_ids":0},
                        "github-username":{"default_category":"Social network","to_ids":0},
                        "github-repository":{"default_category":"Social network","to_ids":0},
                        "github-organisation":{"default_category":"Social network","to_ids":0},
                        "jabber-id":{"default_category":"Social network","to_ids":0},
                        "twitter-id":{"default_category":"Social network","to_ids":0},
                        "first-name":{"default_category":"Person","to_ids":0},
                        "middle-name":{"default_category":"Person","to_ids":0},
                        "last-name":{"default_category":"Person","to_ids":0},
                        "date-of-birth":{"default_category":"Person","to_ids":0},
                        "place-of-birth":{"default_category":"Person","to_ids":0},
                        "gender":{"default_category":"Person","to_ids":0},
                        "passport-number":{"default_category":"Person","to_ids":0},
                        "passport-country":{"default_category":"Person","to_ids":0},
                        "passport-expiration":{"default_category":"Person","to_ids":0},
                        "redress-number":{"default_category":"Person","to_ids":0},
                        "nationality":{"default_category":"Person","to_ids":0},
                        "visa-number":{"default_category":"Person","to_ids":0},
                        "issue-date-of-the-visa":{"default_category":"Person","to_ids":0},
                        "primary-residence":{"default_category":"Person","to_ids":0},
                        "country-of-residence":{"default_category":"Person","to_ids":0},
                        "special-service-request":{"default_category":"Person","to_ids":0},
                        "frequent-flyer-number":{"default_category":"Person","to_ids":0},
                        "travel-details":{"default_category":"Person","to_ids":0},
                        "payment-details":{"default_category":"Person","to_ids":0},
                        "place-port-of-original-embarkation":{"default_category":"Person","to_ids":0},
                        "place-port-of-clearance":{"default_category":"Person","to_ids":0},
                        "place-port-of-onward-foreign-destination":{"default_category":"Person","to_ids":0},
                        "passenger-name-record-locator-number":{"default_category":"Person","to_ids":0},
                        "mobile-application-id":{"default_category":"Payload delivery","to_ids":1},
                        "cortex":{"default_category":"External analysis","to_ids":0}
                    },
                    "types":["md5","sha1","sha256","filename","pdb","filename|md5","filename|sha1","filename|sha256",
                             "ip-src","ip-dst","hostname","domain","domain|ip","email-src","email-dst","email-subject",
                             "email-attachment","email-body","float","url","http-method","user-agent","regkey",
                             "regkey|value","AS","snort","pattern-in-file","pattern-in-traffic","pattern-in-memory",
                             "yara","sigma","cookie","vulnerability","attachment","malware-sample","link","comment",
                             "text","hex","other","named pipe","mutex","target-user","target-email","target-machine",
                             "target-org","target-location","target-external","btc","iban","bic","bank-account-nr",
                             "aba-rtn","bin","cc-number","prtn","phone-number","threat-actor","campaign-name",
                             "campaign-id","malware-type","uri","authentihash","ssdeep","imphash","pehash","impfuzzy",
                             "sha224","sha384","sha512","sha512\/224","sha512\/256","tlsh","filename|authentihash",
                             "filename|ssdeep","filename|imphash","filename|impfuzzy","filename|pehash","filename|sha224",
                             "filename|sha384","filename|sha512","filename|sha512\/224","filename|sha512\/256",
                             "filename|tlsh","windows-scheduled-task","windows-service-name","windows-service-displayname",
                             "whois-registrant-email","whois-registrant-phone","whois-registrant-name","whois-registrar",
                             "whois-creation-date","x509-fingerprint-sha1","dns-soa-email","size-in-bytes","counter",
                             "datetime","cpe","port","ip-dst|port","ip-src|port","hostname|port","email-dst-display-name",
                             "email-src-display-name","email-header","email-reply-to","email-x-mailer",
                             "email-mime-boundary","email-thread-index","email-message-id","github-username",
                             "github-repository","github-organisation","jabber-id","twitter-id","first-name","middle-name",
                             "last-name","date-of-birth","place-of-birth","gender","passport-number","passport-country",
                             "passport-expiration","redress-number","nationality","visa-number","issue-date-of-the-visa",
                             "primary-residence","country-of-residence","special-service-request","frequent-flyer-number",
                             "travel-details","payment-details","place-port-of-original-embarkation",
                             "place-port-of-clearance","place-port-of-onward-foreign-destination",
                             "passenger-name-record-locator-number","mobile-application-id","cortex"
                    ],
                    "categories":["Internal reference","Targeting data","Antivirus detection","Payload delivery",
                             "Artifacts dropped","Payload installation","Persistence mechanism","Network activity",
                             "Payload type","Attribution","External analysis","Financial fraud","Support Tool",
                             "Social network","Person","Other"
                    ],
                    "category_type_mappings":{"Internal reference":["text","link","comment","other","hex"],
                             "Targeting data":["target-user","target-email","target-machine","target-org","target-location",
                                               "target-external","comment"],
                             "Antivirus detection":["link","comment","text","hex","attachment","other"],
                             "Payload delivery":["md5","sha1","sha224","sha256","sha384","sha512","sha512\/224",
                                                 "sha512\/256","ssdeep","imphash","impfuzzy","authentihash","pehash",
                                                 "tlsh","filename","filename|md5","filename|sha1","filename|sha224",
                                                 "filename|sha256","filename|sha384","filename|sha512",
                                                 "filename|sha512\/224","filename|sha512\/256","filename|authentihash",
                                                 "filename|ssdeep","filename|tlsh","filename|imphash","filename|impfuzzy",
                                                 "filename|pehash","ip-src","ip-dst","ip-dst|port","ip-src|port","hostname",
                                                 "domain","email-src","email-dst","email-subject","email-attachment",
                                                 "email-body","url","user-agent","AS","pattern-in-file","pattern-in-traffic",
                                                 "yara","sigma","attachment","malware-sample","link","malware-type","comment",
                                                 "text","hex","vulnerability","x509-fingerprint-sha1","other","hostname|port",
                                                 "email-dst-display-name","email-src-display-name","email-header",
                                                 "email-reply-to","email-x-mailer","email-mime-boundary","email-thread-index",
                                                 "email-message-id","mobile-application-id","whois-registrant-email"],
                             "Artifacts dropped":["md5","sha1","sha224","sha256","sha384","sha512","sha512\/224",
                                            "sha512\/256","ssdeep","imphash","impfuzzy","authentihash","filename","filename|md5",
                                            "filename|sha1","filename|sha224","filename|sha256","filename|sha384",
                                            "filename|sha512","filename|sha512\/224","filename|sha512\/256",
                                            "filename|authentihash","filename|ssdeep","filename|tlsh","filename|imphash",
                                            "filename|impfuzzy","filename|pehash","regkey","regkey|value","pattern-in-file",
                                            "pattern-in-memory","pdb","yara","sigma","attachment","malware-sample","named pipe",
                                            "mutex","windows-scheduled-task","windows-service-name",
                                            "windows-service-displayname","comment","text","hex","x509-fingerprint-sha1",
                                            "other","cookie"],
                             "Payload installation":["md5","sha1","sha224","sha256","sha384","sha512","sha512\/224",
                                            "sha512\/256","ssdeep","imphash","impfuzzy","authentihash","pehash","tlsh",
                                            "filename","filename|md5","filename|sha1","filename|sha224","filename|sha256",
                                            "filename|sha384","filename|sha512","filename|sha512\/224","filename|sha512\/256",
                                            "filename|authentihash","filename|ssdeep","filename|tlsh","filename|imphash",
                                            "filename|impfuzzy","filename|pehash","pattern-in-file","pattern-in-traffic",
                                            "pattern-in-memory","yara","sigma","vulnerability","attachment","malware-sample",
                                            "malware-type","comment","text","hex","x509-fingerprint-sha1",
                                            "mobile-application-id","other"],
                             "Persistence mechanism":["filename","regkey","regkey|value","comment","text","other","hex"],
                             "Network activity":["ip-src","ip-dst","ip-dst|port","ip-src|port","port","hostname","domain",
                                            "domain|ip","email-dst","url","uri","user-agent","http-method","AS","snort",
                                            "pattern-in-file","pattern-in-traffic","attachment","comment","text",
                                            "x509-fingerprint-sha1","other","hex","cookie"],
                             "Payload type":["comment","text","other"],
                             "Attribution":["threat-actor","campaign-name","campaign-id","whois-registrant-phone",
                                            "whois-registrant-email","whois-registrant-name","whois-registrar",
                                            "whois-creation-date","comment","text","x509-fingerprint-sha1","other"],
                             "External analysis":["md5","sha1","sha256","filename","filename|md5","filename|sha1",
                                            "filename|sha256","ip-src","ip-dst","ip-dst|port","ip-src|port","hostname",
                                            "domain","domain|ip","url","user-agent","regkey","regkey|value","AS","snort",
                                            "pattern-in-file","pattern-in-traffic","pattern-in-memory","vulnerability",
                                            "attachment","malware-sample","link","comment","text","x509-fingerprint-sha1",
                                            "github-repository","other","cortex"],
                             "Financial fraud":["btc","iban","bic","bank-account-nr","aba-rtn","bin","cc-number","prtn",
                                            "phone-number","comment","text","other","hex"],
                             "Support Tool":["link","text","attachment","comment","other","hex"],
                             "Social network":["github-username","github-repository","github-organisation","jabber-id",
                                            "twitter-id","email-src","email-dst","comment","text","other","whois-registrant-email"],
                             "Person":["first-name","middle-name","last-name","date-of-birth","place-of-birth","gender",
                                            "passport-number","passport-country","passport-expiration","redress-number",
                                            "nationality","visa-number","issue-date-of-the-visa","primary-residence",
                                            "country-of-residence","special-service-request","frequent-flyer-number",
                                            "travel-details","payment-details","place-port-of-original-embarkation",
                                            "place-port-of-clearance","place-port-of-onward-foreign-destination",
                                            "passenger-name-record-locator-number","comment","text","other","phone-number"],
                             "Other":["comment","text","other","size-in-bytes","counter","datetime","cpe","port","float","hex",
                                            "phone-number"]
                             }
                     }
                 }
             ),
         content_type='application/json',
    )

    # Mock the creation of an event
    # (This is the third thing PyMISP does after authentication) 
    httpretty.register_uri(
        httpretty.POST,
        'http://misp.host.tld/events',
        body=json.dumps({
            "Event": {
                "id": "1",
                "orgc_id": "1",
                "org_id": "1",
                "date": "2015-12-23",
                "threat_level_id": "4",
                "info": "CA-TEST-STIX | Test STIX data",
                "published": False,
                "uuid": "590980a2-154c-47fb-b494-26660a00020f",
                "attribute_count": "0",
                "analysis": "0",
                "timestamp": "1510273227",
                "distribution": "0",
                "proposal_email_lock": False,
                "locked": False,
                "publish_timestamp": "0",
                "sharing_group_id": "0",
                "disable_correlation": False,
                "event_creator_email": "admin@admin.test",
                "Org": {
                    "id": "1",
                    "name": "ORGNAME",
                    "uuid": "5a034cd3-74bc-458e-af13-7843b8dab993"
                },
                "Orgc": {
                    "id": "1",
                    "name": "ORGNAME",
                    "uuid": "5a034cd3-74bc-458e-af13-7843b8dab993"
                },
                "Attribute": [],
                "ShadowAttribute": [],
                "RelatedEvent": [],
                "Galaxy": [],
                "Object": []
            }
        }),
        content_type='application/json',
    )

    # Mock the retrieval of tags
    # (This is the fourth thing PyMISP does after authentication) 
    httpretty.register_uri(
        httpretty.GET,
        'http://misp.host.tld/tags',
        body=json.dumps({'Tag': []}),
        content_type='application/json',
    )

    # Mock adding an attribute to a event 1.
    # (This is the fifth thing PyMISP does after authentication)
    httpretty.register_uri(
        httpretty.POST,
        'http://misp.host.tld/attributes/add/1',
        body=attribute_request_callback,
        content_type='application/json',
    )



    # Now that we have mocked a fake MISP server with the above responses,
    # We actually execute the MISP transform/publish code

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

    # At this point, the MISP transform/ublish code has run, and httpretty
    # has a list of the HTTP requests and responses sent by cti-toolkit,
    # PyMISP and the mocked MISP server

    # Get a list of the requests that the PyMISP library made
    # We need to test the reqests, not the responses, as we're testing
    # the MISP Transform code and PyMISP... not the MISP Server
    reqs = list(httpretty.httpretty.latest_requests)

    # Check that the "get version" request includes the MISP key.
    r_get_version = reqs[0]
    assert r_get_version.path == '/servers/getPyMISPVersion.json'
    assert r_get_version.headers.dict['authorization'] == misp_args['misp_key']

    # Check that the event creation request includes basic information.
    # TODO - change assertion so that it complies with the schema appropriate to the stix_version
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

    # Check that PyMISP then tried creating related attrubutes
    # for all the content in the STIX TEST XML documents
    # We do this by gathering all the POSTed data from all the 
    # attribute/add/1 requests PyMISP sent earlier, and we
    # compare them with the expected requests we should be sending. 
    # If they are the same then the test passes.
    obs_attributes = sorted([json.loads(request.body)
                             for request
                             in reqs[4:]])

    test_obs_attributes = sorted([
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'11111111111111112977fa0588bd504a',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'ccccccccccccccc33574c79829dc1ccf',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'11111111111111133574c79829dc1ccf',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'11111111111111111f2601b4d21660fb',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'md5',
            u'value': u'1111111111b42b57f518197d930471d9',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'mutex',
            u'value': u'\\BaseNamedObjects\\MUTEX_0001',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'mutex',
            u'value': u'\\BaseNamedObjects\\WIN_ABCDEF',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'mutex',
            u'value': u'\\BaseNamedObjects\\iurlkjashdk',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'regkey|value',
            u'value': u'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|hotkey\\%APPDATA%\\malware.exe -st',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'sha1',
            u'value': u'893fb19ac24eabf9b1fe1ddd1111111111111111',
        },
        {
            u'category': u'Artifacts dropped',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'sha256',
            u'value': u'11111111111111119f167683e164e795896be3be94de7f7103f67c6fde667bdf',
        },
        {
            u'category': u'Network activity',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'domain',
            u'value': u'bad.domain.org',
        },
        {
            u'category': u'Network activity',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'domain',
            u'value': u'dnsupdate.dyn.net',
        },
        {
            u'category': u'Network activity',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'domain',
            u'value': u'free.stuff.com',
        },
        {
            u'category': u'Network activity',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'ip-dst',
            u'value': u'183.82.180.95',
        },

        {
            u'category': u'Network activity',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'ip-dst',
            u'value': u'111.222.33.44',
        },
        {
            u'category': u'Network activity',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'ip-dst',
            u'value': u'158.164.39.51',
        },
        {
            u'category': u'Network activity',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'url',
            u'value': u'http://host.domain.tld/path/file',
        },
        {
            u'category': u'Network activity',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'user-agent',
            u'value': u'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36',
        },
        {
            u'category': u'Payload delivery',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'email-src',
            u'value': u'sender@domain.tld',
        },
        {
            u'category': u'Payload delivery',
            u'disable_correlation': False,
            u'to_ids': True,
            u'type': u'email-subject',
            u'value': u'Important project details',
        },
    ])

    for (attr, test_attr,) in zip(obs_attributes, test_obs_attributes):
        assert attr == test_attr
