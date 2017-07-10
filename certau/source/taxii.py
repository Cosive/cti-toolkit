from StringIO import StringIO

from libtaxii.messages_11 import PollResponse

from certau.lib.taxii.util import file_name_for_content_block
from certau.source.base import StixSource


class TaxiiPollResponseSource(StixSource):
    """Return STIX packages obtained from a TAXII poll response.

    Args:
        poll_response: a libtaxii PollResponse message
        poll_url: the URL used for sending the poll request
        collection: the collection that was polled
    """

    def __init__(self, poll_response, poll_url):
        super(TaxiiPollResponseSource, self).__init__()

        if not isinstance(poll_response, PollResponse):
            raise Exception('poll_response not a valid libtaxii PollResponse')

        self.poll_response = poll_response
        self.poll_url = poll_url
        self.collection = poll_response.collection_name
        self._source_items = poll_response.content_blocks

    def io_for_source_item(self, source_item):
        return StringIO(source_item.content)

    def file_name_for_source_item(self, content_block):
        return file_name_for_content_block(content_block, self.collection)
