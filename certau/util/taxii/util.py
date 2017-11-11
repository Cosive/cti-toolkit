import datetime

from libtaxii.common import gen_filename
from libtaxii.constants import *


def file_name_for_content_block(content_block, collection):
    # Shamelessly mimics libtaxii (for compatability).
    format_for_binding_id = {
        CB_STIX_XML_10: '_STIX10_',
        CB_STIX_XML_101: '_STIX101_',
        CB_STIX_XML_11: '_STIX11_',
        CB_STIX_XML_111: '_STIX111_',
    }
    binding_id = content_block.content_binding.binding_id
    if binding_id in format_for_binding_id:
        format_ = format_for_binding_id[binding_id]
        extension = '.xml'
    else:
        format_ = ''
        extension = ''

    if content_block.timestamp_label:
        date_string = 't' + content_block.timestamp_label.isoformat()
    else:
        date_string = 's' + datetime.datetime.now().isoformat()

    return gen_filename(collection, format_, date_string, extension)
