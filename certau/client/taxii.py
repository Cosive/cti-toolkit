"""This module provides a simple TAXII client for polling a TAXII server.

The :py:class:`certau.client.SimpleTaxiiClient` class
provides a simple interface for polling a collection on a TAXII server and
returning the response. It supports SSL (certificate-based)
authentication in addition to a username and password.
"""

import logging
import sys

import libtaxii as t
from libtaxii.clients import HttpClient
import libtaxii.messages_11 as tm

import dateutil.parser


class SimpleTaxiiClient(HttpClient):
    """A simple interface to the libtaxii libraries for polling a TAXII server.

    Args:
        options: an options object containing configuration options (see below)

    Options used by this class are listed under the heading 'Other Parameters'
    below (these are attributes of the options object).

    Other Parameters:
        hostname: the name of the TAXII server
        collection: the collection on the TAXII server to poll
        path: the URL path for the collection
        ssl: use SSL when connecting to the TAXII server
        username: a username for password-based authentication
        password: a password for password-based authentication
        key: a private key file for SSL certificate-based authentication
        cert: a certificate file for SSL certificate-based authentication
        begin_ts: a timestamp to describe the earliest content to be returned
                  by the TAXII server
        end_ts: a timestamp to describe the most recent content to be returned
                by the TAXII server
        subscription_id: a subscription ID to include with the poll request
    """

    def __init__(self, options):
        super(SimpleTaxiiClient, self).__init__()

        self._options = options
        self._logger = logging.getLogger()

        if options.ssl and options.username:
            self._logger.debug(
                "AUTH - using CERT (%s) and User creds (%s:%s)",
                options.cert, options.username, options.password
            )
            self.set_use_https(True)
            self.set_auth_type(HttpClient.AUTH_CERT_BASIC)
            self.set_auth_credentials({
                'key_file': options.key,
                'cert_file': options.cert,
                'username': options.username,
                'password': options.password
            })
        elif options.ssl:
            self._logger.debug("AUTH - using CERT (%s)", options.cert)
            self.set_use_https(True)
            self.set_auth_type(HttpClient.AUTH_CERT)
            self.set_auth_credentials({
                'key_file': options.key,
                'cert_file': options.cert
            })
        else:
            self._logger.debug(
                "AUTH - using user creds (%s:%s)",
                options.username, options.password
            )
            self.set_auth_type(HttpClient.AUTH_BASIC)
            self.set_auth_credentials({
                'username': options.username,
                'password': options.password
            })

    def create_poll_request(self):
        try:
            if self._options.begin_ts:
                begin_ts = dateutil.parser.parse(self._options.begin_ts)
                if not begin_ts.tzinfo:
                    raise ValueError
            else:
                begin_ts = None

            if self._options.end_ts:
                end_ts = dateutil.parser.parse(self._options.end_ts)
                if not end_ts.tzinfo:
                    raise ValueError
            else:
                end_ts = None

        except ValueError:
            self._logger.error(
                "Unable to parse timestamp value. Timestamp should include both date and time "
                "information along with a timezone or UTC offset (e.g., YYYY-MM-DDTHH:MM:SS.ssssss+/-hh:mm). "
                "Aborting poll."
            )
            sys.exit()

        create_kwargs = {
            'message_id': tm.generate_message_id(),
            'collection_name': self._options.collection,
            'exclusive_begin_timestamp_label': begin_ts,
            'inclusive_end_timestamp_label': end_ts
        }

        if self._options.subscription_id:
            create_kwargs['subscription_id'] = self._options.subscription_id
        else:
            create_kwargs['poll_parameters'] = tm.PollRequest.PollParameters()

        poll_req = tm.PollRequest(**create_kwargs)
        return poll_req

    def send_poll_request(self):
        """Send a poll request to the configured server/collection and return the poll response.

        Returns:
            a TAXII poll response message. On failure None is returned and an error logged.
        """
        poll_request1 = self.create_poll_request()
        self._logger.debug("Request generated: using collection name - %s", self._options.collection)

        http_response = self.call_taxii_service2(
            self._options.hostname, self._options.path,
            t.VID_TAXII_XML_11, poll_request1.to_xml()
        )
        self._logger.debug("TAXII response received")
        self._logger.debug("HTTP response %s", http_response.__class__.__name__)

        taxii_message = t.get_message_from_http_response(
            http_response, poll_request1.message_id)

        if taxii_message.message_type == tm.MSG_POLL_RESPONSE:
            return taxii_message
        else:
            self._logger.error('TAXII response not a Poll response as expected.')
            return None
