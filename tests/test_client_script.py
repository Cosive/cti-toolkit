"""TAXII command-line client tests."""
import os

from certau.scripts import stixtransclient

import certau
import stix


def test_text_file_basic_transform(client_wrapper):
    """Test the text file loading."""
    client_wrapper.set_command_line([
        '--file',
        os.path.join('tests', 'CA-TEST-STIX.xml'),
        '--text',
    ])

    stixtransclient.main()

    package, _class, kwargs = client_wrapper.last_args()
    assert isinstance(package, stix.core.STIXPackage)
    assert _class is certau.transform.StixCsvTransform
    assert kwargs == {}


def test_bro_with_source_flag_sets_source(client_wrapper):
    """Test a Bro transform with the '--source' flag sets the source."""
    client_wrapper.set_command_line([
        '--file',
        os.path.join('tests', 'CA-TEST-STIX.xml'),
        '--bro',
        '--source',
        'Custom Bro indicator source',
    ])

    stixtransclient.main()

    _, _, kwargs = client_wrapper.last_args()
    assert kwargs['source'] == 'Custom Bro indicator source'



def test_bro_no_notice_flag_sets_do_notice_to_f(client_wrapper):
    """Test the '--bro-no-notice' flag sets meta.do_notice to 'F'."""
    client_wrapper.set_command_line([
        '--file',
        os.path.join('tests', 'CA-TEST-STIX.xml'),
        '--bro',
        '--bro-no-notice',
    ])

    stixtransclient.main()

    _, _, kwargs = client_wrapper.last_args()
    assert kwargs['do_notice'] == 'F'
