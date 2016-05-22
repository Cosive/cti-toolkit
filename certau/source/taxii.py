import os
import sys
import logging
from StringIO import StringIO

import dateutil.parser
from libtaxii import get_message_from_http_response, VID_TAXII_XML_11
from libtaxii.messages_11 import PollRequest, MSG_POLL_RESPONSE
from libtaxii.messages_11 import generate_message_id
from libtaxii.clients import HttpClient
from libtaxii.scripts import TaxiiScript

from .base import StixSource


class SimpleTaxiiClient(HttpClient, StixSource):
    """A simple interface to the libtaxii libraries for polling a TAXII server.

    The :py:class:`certau.client.SimpleTaxiiClient` class
    provides a simple interface for polling a collection on a TAXII server and
    returning the response. It supports SSL (certificate-based)
    authentication in addition to a username and password.

    Args:
        hostname: the name of the TAXII server
        path: the URL path for the collection
        collection: the collection on the TAXII server to poll
        use_ssl: use SSL when connecting to the TAXII server
        username: a username for password-based authentication
        password: a password for password-based authentication
        port: the port to connect to on the TAXII server
        key_file: a private key file for SSL certificate-based authentication
        cert_file: a certificate file for SSL certificate-based authentication
        begin_ts: a timestamp to describe the earliest content to be returned
                  by the TAXII server
        end_ts: a timestamp to describe the most recent content to be returned
                by the TAXII server
        subscription_id: a subscription ID to include with the poll request
    """

    def __init__(self, hostname, path, collection,
                 use_ssl=False, username=None, password=None, port=None, 
                 key_file=None, cert_file=None, ca_file=None, begin_ts=None,
                 end_ts=None, subscription_id=None):
        super(SimpleTaxiiClient, self).__init__()

        self._logger = logging.getLogger()
        self._hostname = hostname
        self._port = port
        self._path = path
        self._collection = collection
        self._begin_ts = begin_ts
        self._end_ts = end_ts
        self._subscription_id = subscription_id

        self.set_use_https(use_ssl)
        if ca_file:
            self._logger.debug(
                "SSL - verification using file (%s)",
                ca_file
            )
            self.set_verify_server(verify_server=True, ca_file=ca_file)

        if use_ssl and username:
            self._logger.debug(
                "AUTH - using CERT (%s) and User creds (%s:%s)",
                cert_file, username, password
            )
            self.set_auth_type(HttpClient.AUTH_CERT_BASIC)
            self.set_auth_credentials({
                'key_file': key_file,
                'cert_file': cert_file,
                'username': username,
                'password': password,
            })
        elif use_ssl:
            self._logger.debug("AUTH - using CERT (%s)", cert_file)
            self.set_auth_type(HttpClient.AUTH_CERT)
            self.set_auth_credentials({
                'key_file': key_file,
                'cert_file': cert_file,
            })
        else:
            self._logger.debug(
                "AUTH - using user creds (%s:%s)",
                username, password
            )
            self.set_auth_type(HttpClient.AUTH_BASIC)
            self.set_auth_credentials({
                'username': username,
                'password': password,
            })

        # Set the index and the content blocks
        self._cb_index = 0
        self._poll_response = None

    def create_poll_request(self):
        """Create a poll request message using supplied parameters."""
        try:
            if self._begin_ts:
                begin_ts = dateutil.parser.parse(self._begin_ts)
                if not begin_ts.tzinfo:
                    raise ValueError
            else:
                begin_ts = None

            if self._end_ts:
                end_ts = dateutil.parser.parse(self._end_ts)
                if not end_ts.tzinfo:
                    raise ValueError
            else:
                end_ts = None

        except ValueError:
            self._logger.error(
                "Unable to parse timestamp value. Timestamp should include " +
                "both date and time information along with a timezone or " +
                "UTC offset (e.g., YYYY-MM-DDTHH:MM:SS.ssssss+/-hh:mm). " +
                "Aborting poll."
            )
            sys.exit()

        request_kwargs = {
            'message_id': generate_message_id(),
            'collection_name': self._collection,
            'exclusive_begin_timestamp_label': begin_ts,
            'inclusive_end_timestamp_label': end_ts,
        }

        if self._subscription_id:
            request_kwargs['subscription_id'] = self._subscription_id
        else:
            request_kwargs['poll_parameters'] = PollRequest.PollParameters()

        return PollRequest(**request_kwargs)

    def send_poll_request(self):
        """Send the poll request to the TAXII server."""
        poll_request1 = self.create_poll_request()
        self._logger.debug(
            "Request generated: using collection name - %s",
            self._collection)

        http_response = self.call_taxii_service2(
            self._hostname,
            self._path,
            VID_TAXII_XML_11,
            poll_request1.to_xml(),
            self._port,
        )
        self._logger.debug("TAXII response received")
        self._logger.debug("HTTP response %s",
                           http_response.__class__.__name__)

        self._poll_response = get_message_from_http_response(
            http_response,
            poll_request1.message_id,
        )

        if self._poll_response.message_type != MSG_POLL_RESPONSE:
            raise Exception('TAXII response not a poll response as expected.')

    def save_content_blocks(self, directory):
        """Save poll response content blocks to given directory."""
        if os.path.exists(directory) and self._poll_response:
            taxii_script = TaxiiScript()
            taxii_script.write_cbs_from_poll_response_11(
                self._poll_response,
                directory,
            )
        elif not self._poll_response:
            raise Exception('no poll response, call send_poll_request() first')
        else:
            raise Exception('output directory for TAXII content blocks ({}) '
                            'does not exist'.format(directory))

    def next_stix_package(self):
        if not self._poll_response:
            raise Exception('no poll response, call send_poll_request() first')
        if self._cb_index < len(self._poll_response.content_blocks):
            content_block = self._poll_response.content_blocks[self._cb_index]
            package_io = StringIO(content_block.content)
            package = self.load_stix_package(package_io)
            self._cb_index += 1
        else:
            package = None
        return package
