import os
import logging
import urlparse

from libtaxii import get_message_from_http_response, VID_TAXII_XML_11
from libtaxii.messages_11 import PollRequest, MSG_POLL_RESPONSE
from libtaxii.messages_11 import generate_message_id
from libtaxii.clients import HttpClient


class SimpleTaxiiClient(HttpClient):
    """A simple interface to libtaxii for sending TAXII client messages.

    Args:
        username: a username for HTTP basic authentication
        password: a password for HTTP basic authentication
        key_file: a file containing a private key
                  (for SSL certificate-based authentication)
        cert_file: a file containing a certificate
                   (for SSL certificate-based authentication)
        ca_file: a file containing the CA's certificate
                 (for verifying the server's certificate)
    """

    def __init__(self, username=None, password=None,
                 key_file=None, cert_file=None, ca_file=None):
        super(SimpleTaxiiClient, self).__init__()
        self._logger = logging.getLogger()

        self.username = username
        self.password = password
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_file = ca_file

    def setup_authentication(self, use_ssl):
        """Setup the appropriate credentials and authentication type.

        Initialises the authentication settings for the connection.

        Args:
            use_ssl: should this connection use SSL
        """
        self.set_use_https(use_ssl)

        credentials = dict()
        if self.username and self.password:
            credentials['username'] = self.username
            credentials['password'] = self.password

        if use_ssl and self.key_file and self.cert_file:
            credentials['key_file'] = self.key_file
            credentials['cert_file'] = self.cert_file

        if credentials:
            self.set_auth_credentials(credentials)

        if self.username and self.password:
            if use_ssl and self.key_file and self.cert_file:
                self.set_auth_type(HttpClient.AUTH_CERT_BASIC)
                self._logger.debug("TAXII authentication using private key "
                                   "(%s), certificate (%s), and credentials "
                                   "for user '%s'", self.key_file,
                                   self.cert_file, self.username)

            else:
                self.set_auth_type(HttpClient.AUTH_BASIC)
                self._logger.debug("TAXII authentication using credentials "
                                   "for user '%s'", self.username)

        elif use_ssl and self.key_file and self.cert_file:
            self.set_auth_type(HttpClient.AUTH_CERT)
            self._logger.debug("TAXII authentication using private key (%s) "
                               "and certificate (%s) only", self.key_file,
                               self.cert_file)

        else:
            self.set_auth_type(HttpClient.AUTH_NONE)
            self._logger.debug("no TAXII authentication")

        # CA certificate verification
        if use_ssl and self.ca_file:
            self.set_verify_server(verify_server=True, ca_file=self.ca_file)
            self._logger.debug("SSL - verification using CA file (%s)",
                               self.ca_file)

    @staticmethod
    def create_poll_request(collection, subscription_id=None,
                            begin_timestamp=None, end_timestamp=None):
        """Create a poll request message using supplied parameters."""

        request_kwargs = {
            'message_id': generate_message_id(),
            'collection_name': collection,
            'exclusive_begin_timestamp_label': begin_timestamp,
            'inclusive_end_timestamp_label': end_timestamp,
        }

        if subscription_id:
            request_kwargs['subscription_id'] = subscription_id
        else:
            request_kwargs['poll_parameters'] = PollRequest.PollParameters()

        return PollRequest(**request_kwargs)

    def send_poll_request(self, poll_request, poll_url):
        """Send the poll request to the TAXII server using the given URL."""

        # Parse the poll_url to get the parts required by libtaxii
        url_parts = urlparse.urlparse(poll_url)

        # Allow credentials to be provided in poll_url
        if url_parts.username and url_parts.password:
            self.username = url_parts.username
            self.password = url_parts.password
            self._logger.debug('updating username and password from poll_url')

        if url_parts.scheme not in ['http', 'https']:
            raise Exception('invalid scheme in poll_url (%s); expected '
                            '"http" or "https"', poll_url)
        use_ssl = True if url_parts.scheme == 'https' else False

        # Initialise the authentication settings
        self.setup_authentication(use_ssl)

        # Send the poll_request
        self._logger.debug('sending poll request using URL: %s', poll_url)
        http_response = self.call_taxii_service2(
            url_parts.hostname,
            url_parts.path,
            VID_TAXII_XML_11,
            poll_request.to_xml(),
            url_parts.port,
        )
        self._logger.debug('response received: %s',
                           http_response.__class__.__name__)

        poll_response = get_message_from_http_response(
            http_response,
            poll_request.message_id,
        )

        if poll_response.message_type != MSG_POLL_RESPONSE:
            raise Exception('expected a TAXII poll response')

        return poll_response
