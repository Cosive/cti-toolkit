from StringIO import StringIO

from certau.lib.taxii.util import file_name_for_content_block
from certau.source.base import StixSourceItem


class TaxiiContentBlockSourceItem(StixSourceItem):

    def __init__(self, content_block, collection):
        self.collection = collection
        super(TaxiiContentBlockSourceItem, self).__init__(content_block)

    def io(self):
        return StringIO(self.source_item.content)

    def file_name(self):
        return file_name_for_content_block(
            content_block=self.source_item,
            collection=self.collection,
        )


class TaxiiContentBlockSource(object):
    """Return STIX packages obtained from a TAXII poll."""

    def __init__(self, content_blocks, collection):
        self.content_blocks = content_blocks
        self.collection = collection

    def source_items(self):
        for content_block in self.content_blocks:
            yield TaxiiContentBlockSourceItem(
                content_block=content_block,
                collection=self.collection,
            )
