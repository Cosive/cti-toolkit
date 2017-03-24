"""TAXII command-line client tests."""
import os
import stixtransclient

import certau
import stix


def test_text_file_basic_transform(stixtransclient_commandline, process_package):
    """Test the text file loading."""
    stixtransclient_commandline.set([
        '--file',
        os.path.join('tests', 'CA-TEST-STIX.xml'),
        '--text'
    ])

    stixtransclient.main()

    package, _class, kwargs = process_package.was_called_with()
    assert isinstance(package, stix.core.STIXPackage)
    assert _class is certau.transform.StixCsvTransform
    assert kwargs == {}
