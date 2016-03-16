import json
import uuid
import logging

from django.test import TestCase
from django.contrib.auth.models import User
from django.db.models.signals import post_save

from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token

from go_http.send import LoggingSender

from .models import Inbound, Outbound, fire_msg_action_if_new
from .tasks import Send_Message, Send_Metric

Send_Metric.vumi_client = lambda x: LoggingSender('go_http.test')
Send_Message.vumi_client_text = lambda x: LoggingSender('go_http.test')
Send_Message.vumi_client_voice = lambda x: LoggingSender('go_http.test')


class RecordingHandler(logging.Handler):

    """ Record logs. """
    logs = None

    def emit(self, record):
        if self.logs is None:
            self.logs = []
        self.logs.append(record)


class APITestCase(TestCase):

    def setUp(self):
        self.client = APIClient()


class AuthenticatedAPITestCase(APITestCase):

    def setUp(self):
        super(AuthenticatedAPITestCase, self).setUp()
        self.username = 'testuser'
        self.password = 'testpass'
        self.user = User.objects.create_user(self.username,
                                             'testuser@example.com',
                                             self.password)
        token = Token.objects.create(user=self.user)
        self.token = token.key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        self.handler = RecordingHandler()
        logger = logging.getLogger('go_http.test')
        logger.setLevel(logging.INFO)
        logger.addHandler(self.handler)

    def check_logs(self, msg):
        if self.handler.logs is None:  # nothing to check
            return False
        if type(self.handler.logs) != list:
            [logs] = self.handler.logs
        else:
            logs = self.handler.logs
        for log in logs:
            print(log)
            if log.msg == msg:
                return True
        return False

    def _replace_post_save_hooks_outbound(self):
        post_save.disconnect(fire_msg_action_if_new, sender=Outbound)

    def _restore_post_save_hooks_outbound(self):
        post_save.connect(fire_msg_action_if_new, sender=Outbound)


class TestVumiMessagesAPI(AuthenticatedAPITestCase):

    def make_outbound(self):
        self._replace_post_save_hooks_outbound()  # don't let fixtures fire
        outbound_message = {
            "to_addr": "+27123",
            "vumi_message_id": "075a32da-e1e4-4424-be46-1d09b71056fd",
            "content": "Simple outbound message",
            "delivered": False,
            "attempts": 1,
            "metadata": {}
        }
        outbound = Outbound.objects.create(**outbound_message)
        self._restore_post_save_hooks_outbound()  # let tests fire tasks
        self.check_logs(
            "Message: u'Simple outbound message' sent to u'+27123'")
        return str(outbound.id)

    def make_inbound(self, in_reply_to):
        inbound_message = {
            "message_id": str(uuid.uuid4()),
            "in_reply_to": in_reply_to,
            "to_addr": "+27123",
            "from_addr": "020",
            "content": "Call delivered",
            "transport_name": "test_voice",
            "transport_type": "voice",
            "helper_metadata": {}
        }
        inbound = Inbound.objects.create(**inbound_message)
        return str(inbound.id)

    def test_create_outbound_data(self):
        post_outbound = {
            "to_addr": "+27123",
            "vumi_message_id": "075a32da-e1e4-4424-be46-1d09b71056fd",
            "content": "Say something",
            "delivered": False,
            "attempts": 0,
            "metadata": {}
        }
        response = self.client.post('/api/v1/outbound/',
                                    json.dumps(post_outbound),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Outbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.version, 1)
        self.assertEqual(str(d.to_addr), "+27123")
        self.assertEqual(d.content, "Say something")
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(d.metadata, {})

    def test_create_outbound_data_simple(self):
        post_outbound = {
            "to_addr": "+27123",
            "delivered": "false",
            "metadata": {
                "voice_speech_url": "https://foo.com/file.mp3"
            }
        }
        response = self.client.post('/api/v1/outbound/',
                                    json.dumps(post_outbound),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Outbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.version, 1)
        self.assertEqual(str(d.to_addr), "+27123")
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(d.metadata, {
            "voice_speech_url": "https://foo.com/file.mp3"
        })

    def test_update_outbound_data(self):
        existing = self.make_outbound()
        patch_outbound = {
            "delivered": "true",
            "attempts": 2
        }
        response = self.client.patch('/api/v1/outbound/%s/' %
                                     existing,
                                     json.dumps(patch_outbound),
                                     content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d = Outbound.objects.get(pk=existing)
        self.assertEqual(d.version, 1)
        self.assertEqual(str(d.to_addr), "+27123")
        self.assertEqual(d.delivered, True)
        self.assertEqual(d.attempts, 2)

    def test_delete_outbound_data(self):
        existing = self.make_outbound()
        response = self.client.delete('/api/v1/outbound/%s/' %
                                      existing,
                                      content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        d = Outbound.objects.filter(id=existing).count()
        self.assertEqual(d, 0)

    def test_create_inbound_data(self):
        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)
        message_id = str(uuid.uuid4())
        post_inbound = {
            "message_id": message_id,
            "in_reply_to": out.vumi_message_id,
            "to_addr": "+27123",
            "from_addr": "020",
            "content": "Call delivered",
            "transport_name": "test_voice",
            "transport_type": "voice",
            "helper_metadata": {}
        }
        response = self.client.post('/api/v1/inbound/',
                                    json.dumps(post_inbound),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Inbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.message_id, message_id)
        self.assertEqual(d.to_addr, "+27123")
        self.assertEqual(d.from_addr, "020")
        self.assertEqual(d.content, "Call delivered")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, "voice")
        self.assertEqual(d.helper_metadata, {})

    def test_update_inbound_data(self):
        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)
        existing = self.make_inbound(out.vumi_message_id)

        patch_inbound = {
            "content": "Opt out"
        }
        response = self.client.patch('/api/v1/inbound/%s/' %
                                     existing,
                                     json.dumps(patch_inbound),
                                     content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d = Inbound.objects.get(pk=existing)
        self.assertEqual(d.to_addr, "+27123")
        self.assertEqual(d.from_addr, "020")
        self.assertEqual(d.content, "Opt out")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, "voice")
        self.assertEqual(d.helper_metadata, {})

    def test_delete_inbound_data(self):
        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)
        existing = self.make_inbound(out.vumi_message_id)
        response = self.client.delete('/api/v1/inbound/%s/' %
                                      existing,
                                      content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        d = Inbound.objects.filter(id=existing).count()
        self.assertEqual(d, 0)

    def test_event_ack(self):
        existing = self.make_outbound()

        d = Outbound.objects.get(pk=existing)
        ack = {
            "message_type": "event",
            "event_id": "b04ec322fc1c4819bc3f28e6e0c69de6",
            "event_type": "ack",
            "user_message_id": d.vumi_message_id,
            "helper_metadata": {},
            "timestamp": "2015-10-28 16:19:37.485612",
            "sent_message_id": "external-id"
        }
        response = self.client.post('/api/v1/events',
                                    json.dumps(ack),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d = Outbound.objects.get(pk=existing)
        self.assertEqual(d.delivered, True)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(d.metadata["ack_timestamp"],
                         "2015-10-28 16:19:37.485612")
        self.assertEquals(False, self.check_logs(
            "Message: u'Simple outbound message' sent to u'+27123'"))

    def test_event_delivery_report(self):
        existing = self.make_outbound()
        d = Outbound.objects.get(pk=existing)
        dr = {
            "message_type": "event",
            "event_id": "b04ec322fc1c4819bc3f28e6e0c69de6",
            "event_type": "delivery_report",
            "user_message_id": d.vumi_message_id,
            "helper_metadata": {},
            "timestamp": "2015-10-28 16:20:37.485612",
            "sent_message_id": "external-id"
        }
        response = self.client.post('/api/v1/events',
                                    json.dumps(dr),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d = Outbound.objects.get(pk=existing)
        self.assertEqual(d.delivered, True)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(d.metadata["delivery_timestamp"],
                         "2015-10-28 16:20:37.485612")
        self.assertEquals(False, self.check_logs(
            "Message: u'Simple outbound message' sent to u'+27123'"))

    def test_event_nack_first(self):
        existing = self.make_outbound()
        d = Outbound.objects.get(pk=existing)
        post_save.connect(fire_msg_action_if_new, sender=Outbound)
        nack = {
            "message_type": "event",
            "event_id": "b04ec322fc1c4819bc3f28e6e0c69de6",
            "event_type": "nack",
            "nack_reason": "no answer",
            "user_message_id": d.vumi_message_id,
            "helper_metadata": {},
            "timestamp": "2015-10-28 16:20:37.485612",
            "sent_message_id": "external-id"
        }
        response = self.client.post('/api/v1/events',
                                    json.dumps(nack),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        c = Outbound.objects.get(pk=existing)
        self.assertEqual(c.delivered, False)
        self.assertEqual(c.attempts, 2)
        self.assertEqual(c.metadata["nack_reason"],
                         "no answer")
        self.assertEquals(True, self.check_logs(
            "Message: 'Simple outbound message' sent to '+27123' "
            "[session_event: new]"))
        # TODO: Bring metrics back
        # self.assertEquals(
        #     True,
        #     self.check_logs("Metric: 'vumimessage.tries' [sum] -> 1"))

    def test_event_nack_last(self):
        # Be assured this is last message attempt
        outbound_message = {
            "to_addr": "+27123",
            "vumi_message_id": "08b34de7-c6da-4853-a74d-9458533ed169",
            "content": "Simple outbound message",
            "delivered": False,
            "attempts": 3,
            "metadata": {}
        }
        failed = Outbound.objects.create(**outbound_message)
        post_save.connect(fire_msg_action_if_new, sender=Outbound)
        nack = {
            "message_type": "event",
            "event_id": "b04ec322fc1c4819bc3f28e6e0c69de6",
            "event_type": "nack",
            "nack_reason": "no answer",
            "user_message_id": failed.vumi_message_id,
            "helper_metadata": {},
            "timestamp": "2015-10-28 16:20:37.485612",
            "sent_message_id": "external-id"
        }
        response = self.client.post('/api/v1/events',
                                    json.dumps(nack),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d = Outbound.objects.get(pk=failed.id)
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 3)  # not moved on as last attempt passed
        self.assertEqual(d.metadata["nack_reason"],
                         "no answer")
        self.assertEquals(False, self.check_logs(
            "Message: u'Simple outbound message' sent to u'+27123'"
            "[session_event: new]"))
        # TODO: Bring metrics back
        # self.assertEquals(
        #     False,
        #     self.check_logs("Metric: 'vumimessage.tries' [sum] -> 1"))
        # self.assertEquals(
        #     True,
        #     self.check_logs("Metric: 'vumimessage.maxretries' [sum] -> 1"))
