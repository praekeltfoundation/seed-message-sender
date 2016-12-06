import json
from go_http.send import LoggingSender

from message_sender.factory import MessageClientFactory
from message_sender.tasks import send_message
from message_sender.tests import AuthenticatedAPITestCase


class TestSendMessage(AuthenticatedAPITestCase):
    """
    Tests related to the send_message task.
    """
    def replace_message_client_factory(self):
        self._patched_message_client_factory_create = (
            MessageClientFactory.create)
        MessageClientFactory.create = staticmethod(
            lambda _: LoggingSender('go_http.test'))

    def restore_message_client_factory(self):
        MessageClientFactory.create = (
            self._patched_message_client_factory_create)

    def test_call_start_end_vumi(self):
        """
        An outbound call should start with us dialling the number, and when
        the person picks up, playing the content and then terminating the call.
        """
        self.replace_message_client_factory()
        outbound = self.make_voice_outbound()
        send_message(outbound.pk)
        outbound.refresh_from_db()

        self.assertTrue(self.check_logs(
            "Message: None sent to '%s' [session_event: new]" % (
                outbound.to_addr)))

        ack = {
            "message_type": "event",
            "event_id": "b04ec322fc1c4819bc3f28e6e0c69de6",
            "event_type": "ack",
            "user_message_id": outbound.vumi_message_id,
            "timestamp": "2015-10-28 16:19:37.485612",
        }
        self.client.post(
            '/api/v1/events', json.dumps(ack), content_type='application/json')

        self.assertTrue(self.check_logs(
            "Message: 'Simple outbound message' sent to '%s' "
            "[session_event: close] "
            "[voice: {'speech_url': 'http://test.com'}]" % (
                outbound.to_addr)))
        self.restore_message_client_factory()

    def test_call_start_end_junebug(self):
        """
        An outbound call should start with us dialling the number, and when
        the person picks up, playing the content and then terminating the call.
        """
        self.replace_message_client_factory()
        outbound = self.make_voice_outbound()
        send_message(outbound.pk)
        outbound.refresh_from_db()

        self.assertTrue(self.check_logs(
            "Message: None sent to '%s' [session_event: new]" % (
                outbound.to_addr)))

        ack = {
            "event_id": "b04ec322fc1c4819bc3f28e6e0c69de6",
            "event_type": "submitted",
            "message_id": outbound.vumi_message_id,
            "timestamp": "2015-10-28 16:19:37.485612",
        }
        self.client.post(
            '/api/v1/events/junebug', json.dumps(ack),
            content_type='application/json')

        self.assertTrue(self.check_logs(
            "Message: 'Simple outbound message' sent to '%s' "
            "[session_event: close] "
            "[voice: {'speech_url': 'http://test.com'}]" % (
                outbound.to_addr)))
        self.restore_message_client_factory()
