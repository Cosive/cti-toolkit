""" Bare minimum mocking of the options that configargparse provides.

    Creating an instance of the certau.transform.StixTransform or
    certau.client.SimpleTaxiiClient classes requires a
    configargparse.Namespace instance as a constructor argument. The
    configargparse.Namespace instance is the result of calling parse_args() on
    a configargparse.ArgumentParser instance. As parse_args() checks the
    command line, environment variables and the disk there will be issues when
    attempting to reliably unit test that module.

    As the configargparse.Namespace instance simply represents the
    configuration as attributes on itself (eg [instance].file is a boolean),
    we can mock that behaviour quite easily.
"""
import collections


class Options(object):
    """ Options-imitating module.
    """
    defaults = {}

    def __init__(self, settings=None):

        # Using defaultdict covers off configargparse's default=None
        self._options = collections.defaultdict(lambda: None, self.defaults)

        # But you can pass in anything you want.
        self._options.update({} if settings is None else settings)

    def __getattr__(self, name):
        return self._options[name]


class TransformOptions(Options):
    """ Options for the transformer.

        See scripts/stixtransclient.py.
    """
    defaults = {
        'file': None,
        'field_separator': '|',
        'source': 'unknown',
    }


class TaxiiClientOptions(Options):
    """ Options for the TAXII client.
    """
    defaults = {
        'collection': 'my_collection',
    }
