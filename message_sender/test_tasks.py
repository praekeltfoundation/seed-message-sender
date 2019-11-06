from datetime import datetime
from unittest.mock import patch

from django.test import TestCase, override_settings

from message_sender.tasks import send_message


class SendMessageTests(TestCase):
    @override_settings(SAFE_TIME_INTERVAL="09:00:00Z/17:00:00Z")
    @patch("message_sender.tasks.send_message.retry")
    @patch("message_sender.tasks.is_in_time_interval")
    def test_retry_outside_of_safe_time(self, is_in_time_interval, retry):
        """
        If we are outside of the safe sending time, then we should retry
        """
        is_in_time_interval.return_value = (False, datetime(2019, 1, 1, 8, 0, 0))
        send_message(None)
        retry.assert_called_once_with(eta=datetime(2019, 1, 1, 8, 0, 0))

    @override_settings(SAFE_TIME_INTERVAL="09:00:00Z/17:00:00Z")
    @patch("message_sender.tasks.send_message.retry")
    @patch("message_sender.tasks.is_in_time_interval")
    def test_no_retry_inside_of_safe_time(self, is_in_time_interval, retry):
        """
        If we are inside the safe sending time, then we should send the message
        """
        is_in_time_interval.return_value = (True, datetime(2019, 1, 1, 8, 0, 0))
        send_message(None)
        retry.assert_not_called()
