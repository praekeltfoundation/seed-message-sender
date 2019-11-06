from datetime import datetime
from pytz import UTC
from unittest import TestCase

from seed_message_sender.utils import is_in_time_interval


class IsInTimeIntervalTests(TestCase):
    def test_is_in_time_interval(self):
        """
        Returns whether the timestamp is within the time interval
        """
        self.assertEqual(
            is_in_time_interval(
                "09:00:00+0200/17:00:00Z", datetime(2019, 1, 1, 8, 0, 0, tzinfo=UTC)
            ),
            (True, datetime(2019, 1, 1, 8, 0, 0, tzinfo=UTC)),
        )
        self.assertEqual(
            is_in_time_interval(
                "09:00:00+0200/17:00:00Z", datetime(2019, 1, 1, 18, 0, 0, tzinfo=UTC)
            ),
            (False, datetime(2019, 1, 2, 7, 0, 0, tzinfo=UTC)),
        )
        self.assertEqual(
            is_in_time_interval(
                "09:00:00+0200/17:00:00Z", datetime(2019, 1, 1, 6, 0, 0, tzinfo=UTC)
            ),
            (False, datetime(2019, 1, 1, 7, 0, 0, tzinfo=UTC)),
        )
