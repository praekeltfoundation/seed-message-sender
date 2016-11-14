from django.test import TestCase, override_settings

from .utils import make_absolute_url


class TestMakeAbsoluteUrl(TestCase):
    @override_settings(USE_SSL=True)
    def test_make_absolute_url_ssl_true(self):
        """
        If USE_SSL is True, then then the url should be using https
        """
        self.assertEqual(
            make_absolute_url('foo'),
            'https://example.com/foo')
        self.assertEqual(
            make_absolute_url('/foo'),
            'https://example.com/foo')

    @override_settings(USE_SSL=False)
    def test_make_absolute_url_ssl_false(self):
        """
        If USE_SSL is False, then then the url should be using http
        """
        self.assertEqual(
            make_absolute_url('foo'),
            'http://example.com/foo')
        self.assertEqual(
            make_absolute_url('/foo'),
            'http://example.com/foo')
