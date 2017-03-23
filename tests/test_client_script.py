"""TAXII command-line client tests."""
import sys
import stixtransclient


def test_bro_flag(process_package_args):
    """Test the -b or --bro flags do a StixBroIntelTransform."""

    # configargparse's import of sys.argv needs to be haxored :)

    stixtransclient.main()

#    x._process_package(1, 2, 3)

    assert process_package_args == [1, 2, 3]

#    x._process_package(1, 2, 8)

#    assert process_package_args == [1, 2, 8]
