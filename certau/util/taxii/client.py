import os
import logging
import urlparse

from libtaxii import get_message_from_http_response, VID_TAXII_XML_11
from libtaxii.messages_11 import PollRequest, PollFulfillmentRequest
from libtaxii.messages_11 import PollResponse, generate_message_id
from libtaxii.clients import HttpClient

from certau import version_string


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

        self.poll_end_time = None

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

        request_kwargs = dict(
            message_id=generate_message_id(),
            collection_name=collection,
            exclusive_begin_timestamp_label=begin_timestamp,
            inclusive_end_timestamp_label=end_timestamp,
        )

        if subscription_id:
            request_kwargs['subscription_id'] = subscription_id
        else:
            request_kwargs['poll_parameters'] = PollRequest.PollParameters()

        return PollRequest(**request_kwargs)

    @staticmethod
    def create_fulfillment_request(collection, result_id, part_number):
        return PollFulfillmentRequest(
            message_id=generate_message_id(),
            collection_name=collection,
            result_id=result_id,
            result_part_number=part_number,
        )

    def send_taxii_message(self, request, host, path, port):
        # Send the request message and return the response
        http_response = self.call_taxii_service2(
            host=host,
            path=path,
            message_binding=VID_TAXII_XML_11,
            post_data=request.to_xml(),
            port=port,
            user_agent='{} (libtaxii)'.format(version_string)
        )
        response = get_message_from_http_response(
            http_response=http_response,
            in_response_to=request.message_id,
        )
        return response

    def poll(self, poll_url, collection, subscription_id=None,
             begin_timestamp=None, end_timestamp=None):
        """Send the TAXII poll request to the server using the given URL."""

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

        request = self.create_poll_request(
            collection=collection,
            subscription_id=subscription_id,
            begin_timestamp=begin_timestamp,
            end_timestamp=end_timestamp,
        )

        self._logger.debug('sending poll request (url=%s, collection=%s)',
                           poll_url, collection)
        response = self.send_taxii_message(
            request=request,
            host=url_parts.hostname,
            path=url_parts.path,
            port=url_parts.port,
        )

        first = True
        while True:
            if not isinstance(response, PollResponse):
                raise Exception('didn\'t get a poll response')

            self._logger.debug('received poll response '
                               '(content_blocks=%d, result_id=%s, more=%s)',
                               len(response.content_blocks),
                               response.result_id,
                               'True' if response.more else 'False')

            # Save end timestamp from first PollResponse
            if first:
                self.poll_end_time = response.inclusive_end_timestamp_label

            if len(response.content_blocks) == 0:
                if first:
                    self._logger.info('poll response contained '
                                      'no content blocks')
                break

            for content_block in response.content_blocks:
                yield content_block

            if not response.more:
                break

            # Send a fulfilment request
            if first:
                # Initialise fulfilment request values
                part_number = response.result_part_number
                result_id = response.result_id
                first = False

            part_number += 1
            request = self.create_fulfillment_request(
                collection=collection,
                result_id=result_id,
                part_number=part_number,
            )

            self._logger.debug('sending fulfilment request '
                               '(result_id=%s, part_number=%d)',
                               result_id, part_number)
            response = self.send_taxii_message(
                request=request,
                host=url_parts.hostname,
                path=url_parts.path,
                port=url_parts.port,
            )
