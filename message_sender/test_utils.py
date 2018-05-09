from datetime import datetime
from django.test import TestCase, override_settings

from .utils import daterange, make_absolute_url


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


class DateRangeTests(TestCase):
    def test_date_range(self):
        """
        daterange should return the list of dates that falls within the range
        """
        self.assertEqual(
            list(daterange(datetime(2017, 1, 1), datetime(2017, 1, 3))),
            [datetime(2017, 1, 1), datetime(2017, 1, 2), datetime(2017, 1, 3)]
        )
