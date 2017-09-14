"""TAXII command-line client tests."""
import os

from certau.scripts import stixtransclient

import certau
import stix
import pytest

#@pytest.mark.filterwarnings('ignore:The use of this field has been deprecated:UserWarning')
@pytest.mark.parametrize("stix_version", [111, 12]) 
def test_text_file_basic_transform(client_wrapper, stix_version):
    """Test the text file loading."""
    client_wrapper.set_command_line([
        '--file',
        ('TEST-STIX-1.2.xml' if stix_version == 12 else 'TEST-STIX-1.1.1.xml'),
        '--text',
    ])

    stixtransclient.main()

    package, _class, kwargs = client_wrapper.last_args()
    assert isinstance(package, stix.core.STIXPackage)
    assert _class is certau.transform.StixCsvTransform
    assert kwargs == dict(
        default_title=None,
        default_description=None,
        default_tlp='AMBER',
    )



@pytest.mark.parametrize("stix_version", [111, 12])
def test_bro_with_source_flag_sets_source(client_wrapper, stix_version):
    """Test a Bro transform with the '--source' flag sets the source."""
    client_wrapper.set_command_line([
        '--file',
        ('TEST-STIX-1.2.xml' if stix_version == 12 else 'TEST-STIX-1.1.1.xml'),
        '--bro',
        '--source',
        'Custom Bro indicator source',
    ])

    stixtransclient.main()

    _, _, kwargs = client_wrapper.last_args()
    assert kwargs['source'] == 'Custom Bro indicator source'


@pytest.mark.parametrize("stix_version", [111, 12])
def test_bro_no_notice_flag_sets_do_notice_to_f(client_wrapper, stix_version):
    """Test the '--bro-no-notice' flag sets meta.do_notice to 'F'."""
    client_wrapper.set_command_line([
        '--file',
        ('TEST-STIX-1.2.xml' if stix_version == 12 else 'TEST-STIX-1.1.1.xml'),
        '--bro',
        '--bro-no-notice',
    ])

    stixtransclient.main()

    _, _, kwargs = client_wrapper.last_args()
    assert kwargs['do_notice'] == 'F'
