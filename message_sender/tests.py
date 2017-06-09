import json
import uuid
import logging
import responses

try:
    from urllib.parse import urlparse, urlencode
except ImportError:
    from urlparse import urlparse
    from urllib import urlencode

from datetime import timedelta

from celery.exceptions import Retry
from datetime import datetime
from django.test import TestCase, override_settings
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.db.models.signals import post_save
from django.conf import settings
from django.utils import timezone
from django.core.management import call_command
from mock import MagicMock
from mock import patch
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token
from rest_hooks.models import Hook
from requests_testadapter import TestAdapter, TestSession
from go_http.metrics import MetricsApiClient
from go_http.send import LoggingSender

from .factory import (
    MessageClientFactory, JunebugApiSender, HttpApiSender,
    JunebugApiSenderException)
from .models import (Inbound, Outbound, OutboundSendFailure, Channel,
                     IdentityLookup)
from .signals import psh_fire_metrics_if_new, psh_fire_msg_action_if_new
from .tasks import (SendMessage, send_message, fire_metric,
                    ConcurrencyLimiter, requeue_failed_tasks)
from .views import fire_delivery_hook
from . import tasks

from seed_message_sender.utils import load_callable

SendMessage.get_client = lambda x, y: LoggingSender('go_http.test')


def make_channels():
    vumi_channel = {
        'channel_id': 'VUMI_TEXT',
        'channel_type': Channel.VUMI_TYPE,
        'default': False,
        'configuration': {
            'VUMI_CONVERSATION_KEY': 'conv-key',
            'VUMI_ACCOUNT_KEY': 'account-key',
            'VUMI_ACCOUNT_TOKEN': 'account-token',
            'VUMI_API_URL': 'http://example.com/'
        },
        'concurrency_limit': 1,
        'message_timeout': 20,
        'message_delay': 10
    }
    Channel.objects.create(**vumi_channel)

    vumi_channel2 = {
        'channel_id': 'VUMI_VOICE',
        'channel_type': Channel.VUMI_TYPE,
        'default': False,
        'configuration': {
            'VUMI_CONVERSATION_KEY': 'conv-key',
            'VUMI_ACCOUNT_KEY': 'account-key',
            'VUMI_ACCOUNT_TOKEN': 'account-token',
            'VUMI_API_URL': 'http://example.com/'
        },
        'concurrency_limit': 1,
        'message_timeout': 20,
        'message_delay': 10
    }
    Channel.objects.create(**vumi_channel2)

    june_channel = {
        'channel_id': 'JUNE_VOICE',
        'channel_type': Channel.JUNEBUG_TYPE,
        'default': False,
        'configuration': {
            'JUNEBUG_API_URL': 'http://example.com/',
            'JUNEBUG_API_AUTH': ('username', 'password'),
            'JUNEBUG_API_FROM': '+4321'
        },
        'concurrency_limit': 1,
        'message_timeout': 120,
        'message_delay': 100
    }
    Channel.objects.create(**june_channel)

    june_channel2 = {
        'channel_id': 'JUNE_TEXT',
        'channel_type': Channel.JUNEBUG_TYPE,
        'default': True,
        'configuration': {
            'JUNEBUG_API_URL': 'http://example.com/',
            'JUNEBUG_API_AUTH': ('username', 'password'),
            'JUNEBUG_API_FROM': '+4321'
        },
        'concurrency_limit': 0,
        'message_timeout': 0,
        'message_delay': 0
    }
    Channel.objects.create(**june_channel2)

    june_channel2 = {
        'channel_id': 'JUNE_VOICE2',
        'channel_type': Channel.JUNEBUG_TYPE,
        'default': False,
        'configuration': {
            'JUNEBUG_API_URL': 'http://example.com/',
            'JUNEBUG_API_AUTH': ('username', 'password'),
            'JUNEBUG_API_FROM': '+4321'
        },
        'concurrency_limit': 2,
        'message_timeout': 20,
        'message_delay': 10
    }
    Channel.objects.create(**june_channel2)


class RecordingAdapter(TestAdapter):

    """ Record the request that was handled by the adapter.
    """
    request = None

    def send(self, request, *args, **kw):
        self.request = request
        return super(RecordingAdapter, self).send(request, *args, **kw)


class RecordingHandler(logging.Handler):

    """ Record logs. """
    logs = None

    def emit(self, record):
        if self.logs is None:
            self.logs = []

        self.logs.append(record)


class MockCache(object):
    def __init__(self):
        self.cache_data = {}

    def get(self, key):
        return self.cache_data.get(key, None)

    def get_or_set(self, key, value, expire=0):
        if key not in self.cache_data:
            self.cache_data[key] = value
            return value
        return self.cache_data[key]

    def add(self, key, value, expire=0):
        if key not in self.cache_data:
            self.cache_data[key] = value
            return True
        return False

    def incr(self, key, value=1):
        if key not in self.cache_data:
            raise(ValueError)
        self.cache_data[key] += value

    def decr(self, key, value=1):
        if key not in self.cache_data:
            raise(ValueError)
        self.cache_data[key] -= value


class APITestCase(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.adminclient = APIClient()
        self.session = TestSession()


class AuthenticatedAPITestCase(APITestCase):

    def make_outbound(self, to_addr='+27123', to_identity='0c03d360',
                      channel=None):

        if channel:
            channel = Channel.objects.get(channel_id=channel)

        self._replace_post_save_hooks_outbound()  # don't let fixtures fire
        outbound_message = {
            "to_addr": to_addr,
            "to_identity": to_identity,
            "vumi_message_id": "075a32da-e1e4-4424-be46-1d09b71056fd",
            "content": "Simple outbound message",
            "delivered": False,
            "attempts": 1,
            "metadata": {},
            "channel": channel
        }
        outbound = Outbound.objects.create(**outbound_message)
        self._restore_post_save_hooks_outbound()  # let tests fire tasks
        return str(outbound.id)

    def make_inbound(self, in_reply_to, from_addr='020', from_identity=''):
        inbound_message = {
            "message_id": str(uuid.uuid4()),
            "in_reply_to": in_reply_to,
            "to_addr": "+27123",
            "from_addr": from_addr,
            "from_identity": from_identity,
            "content": "Call delivered",
            "transport_name": "test_voice",
            "transport_type": "voice",
            "helper_metadata": {}
        }
        inbound = Inbound.objects.create(**inbound_message)
        return str(inbound.id)

    def _replace_get_metric_client(self, session=None):
        return MetricsApiClient(
            auth_token=settings.METRICS_AUTH_TOKEN,
            api_url=settings.METRICS_URL,
            session=self.session)

    def _restore_get_metric_client(self, session=None):
        return MetricsApiClient(
            auth_token=settings.METRICS_AUTH_TOKEN,
            api_url=settings.METRICS_URL,
            session=session)

    def _replace_post_save_hooks_outbound(self):
        post_save.disconnect(
            psh_fire_msg_action_if_new,
            sender=Outbound,
            dispatch_uid='psh_fire_msg_action_if_new'
        )

    def _replace_post_save_hooks_inbound(self):
        post_save.disconnect(
            psh_fire_metrics_if_new,
            sender=Inbound,
            dispatch_uid='psh_fire_metrics_if_new'
        )

    def _restore_post_save_hooks_outbound(self):
        post_save.connect(
            psh_fire_msg_action_if_new,
            sender=Outbound,
            dispatch_uid='psh_fire_msg_action_if_new'
        )

    def _restore_post_save_hooks_inbound(self):
        post_save.connect(
            psh_fire_metrics_if_new,
            sender=Inbound,
            dispatch_uid='psh_fire_metrics_if_new'
        )

    def check_request(
            self, request, method, params=None, data=None, headers=None):
        self.assertEqual(request.method, method)
        if params is not None:
            url = urlparse.urlparse(request.url)
            qs = urlparse.parse_qsl(url.query)
            self.assertEqual(dict(qs), params)
        if headers is not None:
            for key, value in headers.items():
                self.assertEqual(request.headers[key], value)
        if data is None:
            self.assertEqual(request.body, None)
        else:
            self.assertEqual(json.loads(request.body), data)

    def _mount_session(self):
        response = [{
            'name': 'foo',
            'value': 9000,
            'aggregator': 'bar',
        }]
        adapter = RecordingAdapter(json.dumps(response).encode('utf-8'))
        self.session.mount(
            "http://metrics-url/metrics/", adapter)
        return adapter

    def setUp(self):
        super(AuthenticatedAPITestCase, self).setUp()
        self._replace_post_save_hooks_inbound
        tasks.get_metric_client = self._replace_get_metric_client
        self.adapter = self._mount_session()

        self.username = 'testuser'
        self.password = 'testpass'
        self.user = User.objects.create_user(self.username,
                                             'testuser@example.com',
                                             self.password)
        token = Token.objects.create(user=self.user)
        self.token = token.key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.superuser = User.objects.create_superuser('testsu',
                                                       'su@example.com',
                                                       'dummypwd')
        sutoken = Token.objects.create(user=self.superuser)
        self.adminclient.credentials(
            HTTP_AUTHORIZATION='Token %s' % sutoken)

        self.handler = RecordingHandler()
        logger = logging.getLogger('go_http.test')
        logger.setLevel(logging.INFO)
        logger.addHandler(self.handler)
        make_channels()

    def tearDown(self):
        self._restore_post_save_hooks_inbound()
        tasks.get_metric_client = self._restore_get_metric_client

    def check_logs(self, msg):
        if self.handler.logs is None:  # nothing to check
            return False
        if type(self.handler.logs) != list:
            [logs] = self.handler.logs
        else:
            logs = self.handler.logs
        for log in logs:
            logline = log.msg.replace("u'", "'")
            if logline == msg:
                return True
        return False

    def add_identity_search_response(self, msisdn, identity, count=1):
        msisdn = msisdn.replace('+', '%2B')
        results = [{
            "id": identity,
            "version": 1,
            "details": {
                "default_addr_type": "msisdn",
                "addresses": {
                  "msisdn": {
                      msisdn: {}
                  }
                }
            }
        }] * count
        response = {
            "count": count,
            "next": None,
            "previous": None,
            "results": results
        }
        qs = "?details__addresses__msisdn=%s" % msisdn
        responses.add(responses.GET,
                      "%s/identities/search/%s" % (settings.IDENTITY_STORE_URL, qs),  # noqa
                      json=response, status=200,
                      match_querystring=True)

    def add_create_identity_response(self, identity, msisdn):
        # Setup
        identity = {
            "id": identity,
            "version": 1,
            "details": {
                "default_addr_type": "msisdn",
                "addresses": {
                    "msisdn": {
                        msisdn: {}
                    }
                },
                "risk": "high"
            },
            "communicate_through": None,
            "operator": None,
            "created_at": "2016-04-21T09:11:05.725680Z",
            "created_by": 2,
            "updated_at": "2016-06-15T15:09:05.333526Z",
            "updated_by": 2
        }
        responses.add(responses.POST,
                      "%s/identities/" % settings.IDENTITY_STORE_URL,
                      json=identity, status=201)


class TestVumiMessagesAPI(AuthenticatedAPITestCase):

    @responses.activate
    def test_create_outbound_data1(self):

        self.add_identity_search_response('+27123', '0c03d360')

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
        self.assertEqual(str(d.to_identity), "0c03d360")
        self.assertEqual(d.content, "Say something")
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(d.metadata, {})

    @responses.activate
    def test_create_outbound_data_simple(self):

        self.add_identity_search_response('+27123', '0c03d360')

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
        self.assertEqual(str(d.to_identity), "0c03d360")
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(d.metadata, {
            "voice_speech_url": "https://foo.com/file.mp3"
        })
        self.assertEqual(d.channel, None)

    @responses.activate
    def test_create_outbound_data_new_identity(self):

        self.add_identity_search_response('+2712345', None, 0)
        self.add_create_identity_response('0c03d360123', '+2712345')

        post_outbound = {
            "to_addr": "+2712345",
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
        self.assertEqual(str(d.to_addr), "+2712345")
        self.assertEqual(str(d.to_identity), "0c03d360123")
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(d.metadata, {
            "voice_speech_url": "https://foo.com/file.mp3"
        })
        self.assertEqual(d.channel, None)

        [r, create_id_post] = responses.calls

        self.assertEqual(
            json.loads(create_id_post.request.body.decode("utf-8")),
            {
                "details": {
                    "default_addr_type": "msisdn",
                    "addresses": {
                        "msisdn": {
                            "+2712345": {"default": True}
                        }
                    }
                }
            })

    @responses.activate
    def test_create_outbound_data_with_channel(self):

        self.add_identity_search_response('+27123', '0c03d360')

        post_outbound = {
            "to_addr": "+27123",
            "delivered": "false",
            "metadata": {
                "voice_speech_url": "https://foo.com/file.mp3"
            },
            "channel": "JUNE_TEXT"
        }
        response = self.client.post('/api/v1/outbound/',
                                    json.dumps(post_outbound),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Outbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.version, 1)
        self.assertEqual(str(d.to_addr), "+27123")
        self.assertEqual(str(d.to_identity), "0c03d360")
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(d.metadata, {
            "voice_speech_url": "https://foo.com/file.mp3"
        })
        self.assertEqual(d.channel.channel_id, "JUNE_TEXT")

    def test_create_outbound_data_with_channel_unknown(self):

        post_outbound = {
            "to_addr": "+27123",
            "delivered": "false",
            "metadata": {
                "voice_speech_url": "https://foo.com/file.mp3"
            },
            "channel": "JUNE_VOICE_TEST"
        }
        response = self.client.post('/api/v1/outbound/',
                                    json.dumps(post_outbound),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_outbound_without_recipient(self):

        post_outbound = {
            "delivered": "false",
            "metadata": {}
        }
        response = self.client.post('/api/v1/outbound/',
                                    json.dumps(post_outbound),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @responses.activate
    def test_create_outbound_identity_only(self):

        uid = "test-test-test-test"
        # mock identity address lookup
        responses.add(
            responses.GET,
            "%s/identities/%s/addresses/msisdn?default=True&use_communicate_through=True" % (settings.IDENTITY_STORE_URL, uid),  # noqa
            json={
                "count": 1,
                "next": None,
                "previous": None,
                "results": [{"address": "+26773000000"}]
            },
            status=200, content_type='application/json',
            match_querystring=True
        )

        post_outbound = {
            "to_identity": uid,
            "delivered": "false",
            "metadata": {}
        }
        response = self.client.post('/api/v1/outbound/',
                                    json.dumps(post_outbound),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Outbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.version, 1)
        self.assertEqual(d.to_addr, '+26773000000')
        self.assertEqual(d.to_identity, uid)
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(d.metadata, {})
        self.assertEqual(d.channel, None)

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

    def test_created_at_filter_outbound_exists(self):
        existing = Outbound.objects.get(pk=self.make_outbound())
        response = self.client.get('/api/v1/outbound/?%s' % (urlencode({
            'before': (existing.created_at + timedelta(days=1)).isoformat(),
            'after': (existing.created_at - timedelta(days=1)).isoformat(),
        })))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], str(existing.id))

    def test_created_at_filter_outbound_not_exists(self):
        existing = Outbound.objects.get(pk=self.make_outbound())
        response = self.client.get('/api/v1/outbound/?%s' % (urlencode({
            'before': (existing.created_at - timedelta(days=1)).isoformat(),
            'after': (existing.created_at + timedelta(days=1)).isoformat(),
        })))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_to_addr_filter_outbound(self):
        """
        When filtering on to_addr, only the outbound with the specified to
        address should be returned.
        """
        self.make_outbound(to_addr='+1234')
        self.make_outbound(to_addr='+4321')

        response = self.client.get('/api/v1/outbound/?{}'.format(urlencode({
            'to_addr': '+1234'}))
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)

    def test_to_addr_filter_outbound_multiple(self):
        """
        When filtering on to_addr, if multiple values are presented for the
        to address, we should return all outbound messages that match one of
        the to addresses.
        """
        self.make_outbound(to_addr='+1234')
        self.make_outbound(to_addr='+4321')
        self.make_outbound(to_addr='+1111')

        response = self.client.get('/api/v1/outbound/?{}'.format(urlencode((
            ('to_addr', '+1234'),
            ('to_addr', '+4321'))))
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 2)

    def test_to_identity_filter_outbound(self):
        """
        When filtering on to_identity, only outbound messages with that
        identity id should be returned.
        """
        self.make_outbound(to_identity='1234')
        self.make_outbound(to_identity='4321')

        response = self.client.get('/api/v1/outbound/?{}'.format(urlencode((
            ('to_identity', '1234'),
        ))))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)

    def test_to_identity_filter_outbound_multiple(self):
        """
        When filtering on to_identity, if multiple values are presented for the
        identity ID, we should return all outbound messages that match one of
        the identity IDs.
        """
        self.make_outbound(to_identity='1234')
        self.make_outbound(to_identity='4321')
        self.make_outbound(to_identity='1111')

        response = self.client.get('/api/v1/outbound/?{}'.format(urlencode((
            ('to_identity', '1234'),
            ('to_identity', '4321'),
        ))))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 2)

    def test_created_at_ordering_filter_outbound(self):
        """
        We should be able to order the results of the Outbound list endpoint
        by the created_at timestamp.
        """
        out1 = self.make_outbound()
        out2 = self.make_outbound()

        response = self.client.get('/api/v1/outbound/?{}'.format(urlencode({
            'ordering': 'created_at'}))
        )
        self.assertEqual(
            [o['id'] for o in response.data["results"]],
            [out1, out2]
        )

        response = self.client.get('/api/v1/outbound/?{}'.format(urlencode({
            'ordering': '-created_at'}))
        )
        self.assertEqual(
            [o['id'] for o in response.data["results"]],
            [out2, out1]
        )

    def test_from_addr_filter_inbound(self):
        """
        When filtering on from_addr, only the inbounds with the specified from
        address should be returned.
        """
        self.make_inbound('1234', from_addr='+1234')
        self.make_inbound('1234', from_addr='+4321')

        response = self.client.get('/api/v1/inbound/?{}'.format(urlencode({
            'from_addr': '+1234'}))
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)

    def test_from_addr_filter_inbound_multiple(self):
        """
        When filtering on from_addr, if multiple values are presented for the
        from address, we should return all inbound messages that match one of
        the from addresses.
        """
        self.make_inbound('1234', from_addr='+1234')
        self.make_inbound('1234', from_addr='+4321')
        self.make_inbound('1234', from_addr='+1111')

        response = self.client.get('/api/v1/inbound/?{}'.format(urlencode((
            ('from_addr', '+1234'),
            ('from_addr', '+4321'))))
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 2)

    def test_from_identity_filter_inbound(self):
        """
        When filtering on from_identity, only the inbounds with the specified
        identity ID should be returned.
        """
        self.make_inbound('1234', from_identity='1234')
        self.make_inbound('1234', from_identity='4321')

        response = self.client.get('/api/v1/inbound/?{}'.format(urlencode({
            'from_identity': '1234'}))
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)

    def test_from_identity_filter_inbound_multiple(self):
        """
        When filtering on from_identity, if multiple values are presented for
        the from identity IDs, we should return all inbound messages that match
        one of the from identity IDs.
        """
        self.make_inbound('1234', from_identity='1234')
        self.make_inbound('1234', from_identity='4321')
        self.make_inbound('1234', from_identity='1111')

        response = self.client.get('/api/v1/inbound/?{}'.format(urlencode((
            ('from_identity', '1234'),
            ('from_identity', '4321'))))
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 2)

    def test_created_at_ordering_filter_inbound(self):
        """
        We should be able to order the results of the Inbound list endpoint
        by the created_at timestamp.
        """
        in1 = self.make_inbound('1234')
        in2 = self.make_inbound('1234')

        response = self.client.get('/api/v1/inbound/?{}'.format(urlencode({
            'ordering': 'created_at'}))
        )
        self.assertEqual(
            [i['id'] for i in response.data["results"]],
            [in1, in2]
        )

        response = self.client.get('/api/v1/inbound/?{}'.format(urlencode({
            'ordering': '-created_at'}))
        )
        self.assertEqual(
            [i['id'] for i in response.data["results"]],
            [in2, in1]
        )

    @responses.activate
    def test_create_inbound_data_no_limit(self):

        self.add_identity_search_response('020', '0c03d360')

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
        with patch.object(ConcurrencyLimiter, 'decr_message_count') as \
                mock_method:
            response = self.client.post('/api/v1/inbound/',
                                        json.dumps(post_inbound),
                                        content_type='application/json')
            mock_method.assert_not_called()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Inbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.message_id, message_id)
        self.assertEqual(d.to_addr, "+27123")
        self.assertEqual(d.from_addr, "")
        self.assertEqual(d.from_identity, "0c03d360")
        self.assertEqual(d.content, "Call delivered")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, "voice")
        self.assertEqual(d.helper_metadata, {})

    @responses.activate
    def test_create_inbound_data_unknown_msisdn(self):

        self.add_identity_search_response('020', '0c03d360', 0)
        self.add_create_identity_response('0c03d360', '020')

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
        with patch.object(ConcurrencyLimiter, 'decr_message_count') as \
                mock_method:
            response = self.client.post('/api/v1/inbound/',
                                        json.dumps(post_inbound),
                                        content_type='application/json')
            mock_method.assert_not_called()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Inbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.message_id, message_id)
        self.assertEqual(d.to_addr, "+27123")
        self.assertEqual(d.from_addr, "")
        self.assertEqual(d.from_identity, "0c03d360")
        self.assertEqual(d.content, "Call delivered")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, "voice")
        self.assertEqual(d.helper_metadata, {})

    @responses.activate
    def test_create_inbound_data_with_channel(self):

        self.add_identity_search_response('020', '0c03d360')

        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)
        out.last_sent_time = out.created_at
        out.save()
        message_id = str(uuid.uuid4())
        post_inbound = {
            "message_id": message_id,
            "in_reply_to": out.vumi_message_id,
            "to_addr": "+27123",
            "from_addr": "020",
            "content": "Call delivered",
            "transport_name": "test_voice",
            "transport_type": "voice",
            "helper_metadata": {},
            "session_event": "close"
        }
        channel = Channel.objects.get(channel_id='VUMI_VOICE')
        with patch.object(ConcurrencyLimiter, 'decr_message_count') as \
                mock_method:
            response = self.client.post('/api/v1/inbound/VUMI_VOICE/',
                                        json.dumps(post_inbound),
                                        content_type='application/json')
            mock_method.assert_called_once_with(channel, out.created_at)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Inbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.message_id, message_id)
        self.assertEqual(d.to_addr, "+27123")
        self.assertEqual(d.from_addr, "")
        self.assertEqual(d.from_identity, "0c03d360")
        self.assertEqual(d.content, "Call delivered")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, "voice")
        self.assertEqual(d.helper_metadata, {"session_event": "close"})

    @responses.activate
    def test_create_inbound_data_with_concurrency_limiter(self):

        self.add_identity_search_response('020', '0c03d360')

        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)
        out.last_sent_time = out.created_at
        out.save()
        message_id = str(uuid.uuid4())
        post_inbound = {
            "message_id": message_id,
            "in_reply_to": out.vumi_message_id,
            "to_addr": "+27123",
            "from_addr": "020",
            "content": "Call delivered",
            "transport_name": "test_voice",
            "transport_type": "voice",
            "helper_metadata": {},
            "session_event": "close"
        }
        channel = Channel.objects.get(channel_id='JUNE_VOICE')
        with patch.object(ConcurrencyLimiter, 'decr_message_count') as \
                mock_method:
            response = self.client.post('/api/v1/inbound/JUNE_VOICE/',
                                        json.dumps(post_inbound),
                                        content_type='application/json')
            mock_method.assert_called_once_with(channel, out.created_at)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Inbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.message_id, message_id)
        self.assertEqual(d.to_addr, "+27123")
        self.assertEqual(d.from_addr, "")
        self.assertEqual(d.from_identity, "0c03d360")
        self.assertEqual(d.content, "Call delivered")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, "voice")
        self.assertEqual(d.helper_metadata, {"session_event": "close"})

    @responses.activate
    def test_create_inbound_without_vumi_id_with_concurrency_limiter(self):

        self.add_identity_search_response('+27123', '0c03d360')

        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)
        out.last_sent_time = out.created_at
        out.save()
        message_id = str(uuid.uuid4())
        post_inbound = {
            "message_id": message_id,
            "in_reply_to": None,
            "to_addr": "020",
            "from_addr": "+27123",
            "content": "Call delivered",
            "transport_name": "test_voice",
            "transport_type": "voice",
            "helper_metadata": {},
            "session_event": "close"
        }
        channel = Channel.objects.get(channel_id='JUNE_VOICE')
        with patch.object(ConcurrencyLimiter, 'decr_message_count') as \
                mock_method:
            response = self.client.post('/api/v1/inbound/JUNE_VOICE/',
                                        json.dumps(post_inbound),
                                        content_type='application/json')
            mock_method.assert_called_once_with(channel, out.created_at)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Inbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.message_id, message_id)
        self.assertEqual(d.to_addr, "020")
        self.assertEqual(d.from_addr, "")
        self.assertEqual(d.from_identity, "0c03d360")
        self.assertEqual(d.content, "Call delivered")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, "voice")
        self.assertEqual(d.helper_metadata, {"session_event": "close"})

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

    @responses.activate
    def test_create_inbound_event_message(self):

        self.add_identity_search_response('020', '0c03d360')

        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)
        out.last_sent_time = out.created_at
        out.save()
        message_id = str(uuid.uuid4())
        post_inbound = {
            "message_id": message_id,
            "in_reply_to": out.vumi_message_id,
            "to_addr": "0.0.0.0:9001",
            "from_addr": "020",
            "content": "Call delivered",
            "transport_name": "test_voice",
            "transport_type": "voice",
            "helper_metadata": {},
            "session_event": "close"
        }
        channel = Channel.objects.get(channel_id='JUNE_VOICE')

        with patch.object(ConcurrencyLimiter, 'decr_message_count') as \
                mock_method:
            response = self.client.post('/api/v1/inbound/JUNE_VOICE/',
                                        json.dumps(post_inbound),
                                        content_type='application/json')
            mock_method.assert_called_once_with(channel, out.created_at)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Inbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.message_id, message_id)
        self.assertEqual(d.to_addr, "0.0.0.0:9001")
        self.assertEqual(d.from_addr, "")
        self.assertEqual(d.from_identity, "0c03d360")
        self.assertEqual(d.content, "Call delivered")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, "voice")
        self.assertEqual(d.helper_metadata, {"session_event": "close"})

    @patch('message_sender.views.fire_delivery_hook')
    def test_event_ack(self, mock_hook):
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
            "Message: 'Simple outbound message' sent to '+27123'"))
        mock_hook.assert_called_once_with(d)

    @patch('message_sender.views.fire_delivery_hook')
    def test_event_delivery_report(self, mock_hook):
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
            "Message: 'Simple outbound message' sent to '+27123'"))
        mock_hook.assert_called_once_with(d)

    @patch('message_sender.views.fire_delivery_hook')
    def test_event_nack_first(self, mock_hook):
        existing = self.make_outbound()
        d = Outbound.objects.get(pk=existing)
        post_save.connect(
            psh_fire_msg_action_if_new,
            sender=Outbound,
            dispatch_uid='psh_fire_msg_action_if_new'
        )
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
        mock_hook.assert_called_once_with(d)
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
        failed.last_sent_time = failed.created_at
        failed.save()
        post_save.connect(
            psh_fire_msg_action_if_new,
            sender=Outbound,
            dispatch_uid='psh_fire_msg_action_if_new'
        )
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
            "Message: 'Simple outbound message' sent to '+27123'"
            "[session_event: new]"))
        # TODO: Bring metrics back
        # self.assertEquals(
        #     False,
        #     self.check_logs("Metric: 'vumimessage.tries' [sum] -> 1"))
        # self.assertEquals(
        #     True,
        #     self.check_logs("Metric: 'vumimessage.maxretries' [sum] -> 1"))

    @responses.activate
    def test_fire_delivery_hook_max_retries_not_reached(self):
        '''
        This should not fire the hook
        '''
        Hook.objects.create(
            user=self.user, event='outbound.delivery_report',
            target='http://example.com')
        d = Outbound.objects.get(pk=self.make_outbound())
        responses.add(responses.POST, 'http://example.com',
                      status=200, content_type='application/json')

        fire_delivery_hook(d)

        self.assertEqual(len(responses.calls), 0)

    @responses.activate
    def test_fire_delivery_hook_max_retries_reached(self):
        '''
        This should call deliver_hook_wrapper to send data to a web hook
        '''
        hook = Hook.objects.create(
            user=self.user, event='outbound.delivery_report',
            target='http://example.com')
        d = Outbound.objects.get(pk=self.make_outbound())
        d.attempts = 3
        d.save()
        responses.add(responses.POST, 'http://example.com',
                      status=200, content_type='application/json')

        fire_delivery_hook(d)

        [r] = responses.calls
        r = json.loads(r.request.body)
        self.assertEqual(r['hook'], {"id": hook.id, "event": hook.event,
                                     "target": hook.target})
        self.assertEqual(r['data'], {"delivered": False, "to_addr": d.to_addr,
                                     "outbound_id": str(d.id),
                                     "identity": d.to_identity})

    @responses.activate
    def test_fire_delivery_hook_when_delivered(self):
        '''
        This should call deliver_hook_wrapper to send data to a web hook
        '''
        hook = Hook.objects.create(
            user=self.user, event='outbound.delivery_report',
            target='http://example.com')
        d = Outbound.objects.get(pk=self.make_outbound())
        d.delivered = True
        d.save()
        responses.add(responses.POST, 'http://example.com',
                      status=200, content_type='application/json')

        fire_delivery_hook(d)

        [r] = responses.calls
        r = json.loads(r.request.body)
        self.assertEqual(r['hook'], {"id": hook.id, "event": hook.event,
                                     "target": hook.target})
        self.assertEqual(r['data'], {"delivered": True, "to_addr": d.to_addr,
                                     "outbound_id": str(d.id),
                                     "identity": d.to_identity})


class TestJunebugMessagesAPI(AuthenticatedAPITestCase):
    def test_event_missing_fields(self):
        '''
        If there are missing fields in the request, and error response should
        be returned.
        '''
        response = self.client.post(
            '/api/v1/events/junebug', json.dumps({}),
            content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_event_no_message(self):
        '''
        If we cannot find the message for the event, and error response should
        be returned.
        '''
        ack = {
            "event_type": "submitted",
            "message_id": 'bad-message-id',
            "channel-id": "channel-uuid-1234",
            "timestamp": "2015-10-28 16:19:37.485612",
            "event_details": {},
        }
        response = self.client.post(
            '/api/v1/events/junebug', json.dumps(ack),
            content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('message_sender.views.fire_delivery_hook')
    def test_event_ack(self, mock_hook):
        '''A submitted event should update the message object accordingly.'''
        existing = self.make_outbound()

        d = Outbound.objects.get(pk=existing)
        ack = {
            "event_type": "submitted",
            "message_id": d.vumi_message_id,
            "channel-id": "channel-uuid-1234",
            "timestamp": "2015-10-28 16:19:37.485612",
            "event_details": {},
        }

        response = self.client.post(
            '/api/v1/events/junebug', json.dumps(ack),
            content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d = Outbound.objects.get(pk=existing)
        self.assertEqual(d.delivered, True)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(
            d.metadata["ack_timestamp"], "2015-10-28 16:19:37.485612")
        self.assertEquals(False, self.check_logs(
            "Message: 'Simple outbound message' sent to '+27123'"))
        mock_hook.assert_called_once_with(d)

    @patch('message_sender.views.fire_delivery_hook')
    def test_event_nack(self, mock_hook):
        '''
        A rejected event should retry and update the message object accordingly
        '''
        existing = self.make_outbound()
        d = Outbound.objects.get(pk=existing)
        post_save.connect(
            psh_fire_msg_action_if_new,
            sender=Outbound,
            dispatch_uid='psh_fire_msg_action_if_new'
        )
        nack = {
            "event_type": "rejected",
            "message_id": d.vumi_message_id,
            "channel-id": "channel-uuid-1234",
            "timestamp": "2015-10-28 16:19:37.485612",
            "event_details": {"reason": "No answer"},
        }
        response = self.client.post(
            '/api/v1/events/junebug', json.dumps(nack),
            content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        c = Outbound.objects.get(pk=existing)
        self.assertEqual(c.delivered, False)
        self.assertEqual(c.attempts, 2)
        self.assertEqual(
            c.metadata["nack_reason"], {"reason": "No answer"})
        self.assertEquals(True, self.check_logs(
            "Message: 'Simple outbound message' sent to '+27123' "
            "[session_event: new]"))
        mock_hook.assert_called_once_with(d)

    @patch('message_sender.views.fire_delivery_hook')
    def test_event_delivery_succeeded(self, mock_hook):
        '''A successful delivery should update the message accordingly.'''
        existing = self.make_outbound()
        d = Outbound.objects.get(pk=existing)
        dr = {
            "event_type": "delivery_succeeded",
            "message_id": d.vumi_message_id,
            "channel-id": "channel-uuid-1234",
            "timestamp": "2015-10-28 16:19:37.485612",
            "event_details": {},
        }
        response = self.client.post(
            '/api/v1/events/junebug', json.dumps(dr),
            content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d = Outbound.objects.get(pk=existing)
        self.assertEqual(d.delivered, True)
        self.assertEqual(d.attempts, 1)
        self.assertEqual(
            d.metadata["delivery_timestamp"], "2015-10-28 16:19:37.485612")
        self.assertEquals(False, self.check_logs(
            "Message: 'Simple outbound message' sent to '+27123'"))
        mock_hook.assert_called_once_with(d)

    @patch('message_sender.views.fire_delivery_hook')
    def test_event_delivery_failed(self, mock_hook):
        '''
        A failed delivery should retry and update the message accordingly.
        '''
        existing = self.make_outbound()
        d = Outbound.objects.get(pk=existing)
        dr = {
            "event_type": "delivery_failed",
            "message_id": d.vumi_message_id,
            "channel-id": "channel-uuid-1234",
            "timestamp": "2015-10-28 16:19:37.485612",
            "event_details": {},
        }
        response = self.client.post(
            '/api/v1/events/junebug', json.dumps(dr),
            content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d = Outbound.objects.get(pk=existing)
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 2)
        self.assertEqual(
            d.metadata["delivery_failed_reason"], {})
        self.assertEquals(False, self.check_logs(
            "Message: 'Simple outbound message' sent to '+27123'"))
        mock_hook.assert_called_once_with(d)

    @responses.activate
    def test_create_inbound_junebug_message(self):
        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)
        out.last_sent_time = out.created_at
        out.save()
        message_id = str(uuid.uuid4())
        post_inbound = {
            "message_id": message_id,
            "reply_to": "test_id",
            "to": "0.0.0.0:9001",
            "from": out.to_addr,
            "content": "Call delivered",
            "channel_id": "test_voice",
            "channel_data": {"session_event": "close"}
        }
        self.add_identity_search_response(out.to_addr, '0c03d360')
        response = self.client.post('/api/v1/inbound/',
                                    json.dumps(post_inbound),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Inbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.message_id, message_id)
        self.assertEqual(d.to_addr, "0.0.0.0:9001")
        self.assertEqual(d.from_addr, "")
        self.assertEqual(d.from_identity, "0c03d360")
        self.assertEqual(d.content, "Call delivered")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, None)
        self.assertEqual(d.helper_metadata, {"session_event": "close"})

    @responses.activate
    def test_create_inbound_junebug_unknown_msisdn(self):

        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)
        out.last_sent_time = out.created_at
        out.save()
        message_id = str(uuid.uuid4())
        post_inbound = {
            "message_id": message_id,
            "reply_to": "test_id",
            "to": "0.0.0.0:9001",
            "from": out.to_addr,
            "content": "Call delivered",
            "channel_id": "test_voice",
            "channel_data": {"session_event": "close"}
        }
        self.add_identity_search_response(out.to_addr, '0c03d360')
        self.add_create_identity_response('0c03d360', out.to_addr)
        response = self.client.post('/api/v1/inbound/',
                                    json.dumps(post_inbound),
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        d = Inbound.objects.last()
        self.assertIsNotNone(d.id)
        self.assertEqual(d.message_id, message_id)
        self.assertEqual(d.to_addr, "0.0.0.0:9001")
        self.assertEqual(d.from_addr, "")
        self.assertEqual(d.from_identity, "0c03d360")
        self.assertEqual(d.content, "Call delivered")
        self.assertEqual(d.transport_name, "test_voice")
        self.assertEqual(d.transport_type, None)
        self.assertEqual(d.helper_metadata, {"session_event": "close"})


class TestMetricsAPI(AuthenticatedAPITestCase):

    def test_metrics_read(self):
        # Setup
        # Execute
        response = self.client.get('/api/metrics/',
                                   content_type='application/json')
        # Check
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["metrics_available"], [
                'inbounds.created.sum',
                'vumimessage.tries.sum',
                'vumimessage.maxretries.sum',
                'vumimessage.obd.tries.sum',
                'vumimessage.obd.successful.sum',
                'vumimessage.obd.unsuccessful.sum',
                'message.failures.sum',
                'message.sent.sum',
                'sender.send_message.connection_error.sum',
                'sender.send_message.http_error.400.sum',
                'sender.send_message.http_error.401.sum',
                'sender.send_message.http_error.403.sum',
                'sender.send_message.http_error.404.sum',
                'sender.send_message.http_error.500.sum',
                'sender.send_message.timeout.sum',
            ]
        )

    @responses.activate
    def test_post_metrics(self):
        # Setup
        # deactivate Testsession for this test
        self.session = None
        responses.add(responses.POST,
                      "http://metrics-url/metrics/",
                      json={"foo": "bar"},
                      status=200, content_type='application/json')
        # Execute
        response = self.client.post('/api/metrics/',
                                    content_type='application/json')
        # Check
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["scheduled_metrics_initiated"], True)


class TestMetrics(AuthenticatedAPITestCase):

    def test_direct_fire(self):
        # Setup
        adapter = self._mount_session()
        # Execute
        result = fire_metric.apply_async(kwargs={
            "metric_name": 'foo.last',
            "metric_value": 1,
            "session": self.session
        })
        # Check
        self.check_request(
            adapter.request, 'POST',
            data={"foo.last": 1.0}
        )
        self.assertEqual(result.get(),
                         "Fired metric <foo.last> with value <1.0>")

    def test_created_metrics(self):
        # Setup
        adapter = self._mount_session()
        # reconnect metric post_save hook
        post_save.connect(
            psh_fire_metrics_if_new,
            sender=Inbound,
            dispatch_uid='psh_fire_metrics_if_new'
        )
        # make outbound
        existing_outbound = self.make_outbound()
        out = Outbound.objects.get(pk=existing_outbound)

        # Execute
        self.make_inbound(out.vumi_message_id)

        # Check
        self.check_request(
            adapter.request, 'POST',
            data={"inbounds.created.sum": 1.0}
        )
        # remove post_save hooks to prevent teardown errors
        post_save.disconnect(psh_fire_metrics_if_new, sender=Inbound)


class TestHealthcheckAPI(AuthenticatedAPITestCase):

    def test_healthcheck_read(self):
        # Setup
        # Execute
        response = self.client.get('/api/health/',
                                   content_type='application/json')
        # Check
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["up"], True)
        self.assertEqual(response.data["result"]["database"], "Accessible")


class TestUserCreation(AuthenticatedAPITestCase):

    def test_create_user_and_token(self):
        # Setup
        user_request = {"email": "test@example.org"}
        # Execute
        request = self.adminclient.post('/api/v1/user/token/', user_request)
        token = request.json().get('token', None)
        # Check
        self.assertIsNotNone(
            token, "Could not receive authentication token on post.")
        self.assertEqual(
            request.status_code, 201,
            "Status code on /api/v1/user/token/ was %s (should be 201)."
            % request.status_code)

    def test_create_user_and_token_fail_nonadmin(self):
        # Setup
        user_request = {"email": "test@example.org"}
        # Execute
        request = self.client.post('/api/v1/user/token/', user_request)
        error = request.json().get('detail', None)
        # Check
        self.assertIsNotNone(
            error, "Could not receive error on post.")
        self.assertEqual(
            error, "You do not have permission to perform this action.",
            "Error message was unexpected: %s."
            % error)

    def test_create_user_and_token_not_created(self):
        # Setup
        user_request = {"email": "test@example.org"}
        # Execute
        request = self.adminclient.post('/api/v1/user/token/', user_request)
        token = request.json().get('token', None)
        # And again, to get the same token
        request2 = self.adminclient.post('/api/v1/user/token/', user_request)
        token2 = request2.json().get('token', None)

        # Check
        self.assertEqual(
            token, token2,
            "Tokens are not equal, should be the same as not recreated.")

    def test_create_user_new_token_nonadmin(self):
        # Setup
        user_request = {"email": "test@example.org"}
        request = self.adminclient.post('/api/v1/user/token/', user_request)
        token = request.json().get('token', None)
        cleanclient = APIClient()
        cleanclient.credentials(HTTP_AUTHORIZATION='Token %s' % token)
        # Execute
        request = cleanclient.post('/api/v1/user/token/', user_request)
        error = request.json().get('detail', None)
        # Check
        # new user should not be admin
        self.assertIsNotNone(
            error, "Could not receive error on post.")
        self.assertEqual(
            error, "You do not have permission to perform this action.",
            "Error message was unexpected: %s."
            % error)


class TestFormatter(TestCase):

    @override_settings(
        VOICE_TO_ADDR_FORMATTER='message_sender.formatters.noop')
    def test_noop(self):
        cb = load_callable(settings.VOICE_TO_ADDR_FORMATTER)
        self.assertEqual(cb('12345'), '12345')

    @override_settings(
        VOICE_TO_ADDR_FORMATTER='message_sender.formatters.vas2nets_voice')
    def test_vas2nets_voice(self):
        cb = load_callable(settings.VOICE_TO_ADDR_FORMATTER)
        self.assertEqual(cb('+23456'), '9056')
        self.assertEqual(cb('23456'), '9056')

    @override_settings(
        VOICE_TO_ADDR_FORMATTER='message_sender.formatters.vas2nets_text')
    def test_vas2nets_text(self):
        cb = load_callable(settings.VOICE_TO_ADDR_FORMATTER)
        self.assertEqual(cb('+23456'), '23456')
        self.assertEqual(cb('23456'), '23456')


class TestFactory(TestCase):

    def setUp(self):
        super(TestFactory, self).setUp()
        make_channels()

    def test_create_junebug_text(self):
        channel = Channel.objects.get(channel_id="JUNE_TEXT")
        message_sender = MessageClientFactory.create(channel)
        self.assertTrue(isinstance(message_sender, JunebugApiSender))
        self.assertEqual(message_sender.api_url, 'http://example.com/')
        self.assertEqual(message_sender.auth, ('username', 'password'))

    def test_create_junebug_voice(self):
        channel = Channel.objects.get(channel_id="JUNE_VOICE")
        message_sender = MessageClientFactory.create(channel)
        self.assertTrue(isinstance(message_sender, JunebugApiSender))
        self.assertEqual(message_sender.api_url, 'http://example.com/')
        self.assertEqual(message_sender.auth, ('username', 'password'))

    def test_create_vumi_text(self):
        channel = Channel.objects.get(channel_id="VUMI_TEXT")
        message_sender = MessageClientFactory.create(channel)
        self.assertTrue(isinstance(message_sender, HttpApiSender))
        self.assertEqual(
            message_sender.api_url, 'http://example.com/')
        self.assertEqual(message_sender.account_key, 'account-key')
        self.assertEqual(message_sender.conversation_key, 'conv-key')
        self.assertEqual(message_sender.conversation_token, 'account-token')

    def test_create_vumi_voice(self):
        channel = Channel.objects.get(channel_id="VUMI_VOICE")
        message_sender = MessageClientFactory.create(channel)
        self.assertTrue(isinstance(message_sender, HttpApiSender))
        self.assertEqual(
            message_sender.api_url, 'http://example.com/')
        self.assertEqual(message_sender.account_key, 'account-key')
        self.assertEqual(message_sender.conversation_key, 'conv-key')
        self.assertEqual(message_sender.conversation_token, 'account-token')

    def test_create_no_backend_type_specified_default(self):
        '''
        If no message backend is specified, it should use the default channel.
        '''
        message_sender = MessageClientFactory.create()
        self.assertTrue(isinstance(message_sender, JunebugApiSender))
        self.assertEqual(message_sender.api_url, 'http://example.com/')
        self.assertEqual(message_sender.auth, ('username', 'password'))


class TestJunebugAPISender(TestCase):

    def setUp(self):
        super(TestJunebugAPISender, self).setUp()
        make_channels()

    @responses.activate
    def test_send_text(self):
        '''
        Using the send_text function should send a request to Junebug with the
        correct JSON data.
        '''
        responses.add(
            responses.POST, "http://example.com/",
            json={"result": {"message_id": "message-uuid"}}, status=200,
            content_type='application/json')

        channel = Channel.objects.get(channel_id="JUNE_TEXT")
        message_sender = MessageClientFactory.create(channel)
        res = message_sender.send_text('+1234', 'Test', session_event='resume')

        self.assertEqual(res['message_id'], 'message-uuid')

        [r] = responses.calls
        r = json.loads(r.request.body)
        self.assertEqual(r['to'], '+1234')
        self.assertEqual(r['from'], '+4321')
        self.assertEqual(r['content'], 'Test')
        self.assertEqual(r['channel_data']['session_event'], 'resume')
        self.assertEqual(
            r['event_url'], 'http://example.com/api/v1/events/junebug')

    @responses.activate
    def test_send_voice(self):
        '''
        Using the send_voice function should send a request to Junebug with the
        correct JSON data.
        '''
        responses.add(
            responses.POST, "http://example.com/",
            json={"result": {"message_id": "message-uuid"}}, status=200,
            content_type='application/json')

        channel = Channel.objects.get(channel_id="JUNE_VOICE")
        message_sender = MessageClientFactory.create(channel)
        res = message_sender.send_voice(
            '+1234', 'Test', speech_url='http://test.mp3', wait_for='#',
            session_event='resume')

        self.assertEqual(res['message_id'], 'message-uuid')

        [r] = responses.calls
        r = json.loads(r.request.body)
        self.assertEqual(r['to'], '+1234')
        self.assertEqual(r['from'], '+4321')
        self.assertEqual(r['content'], 'Test')
        self.assertEqual(r['channel_data']['session_event'], 'resume')
        self.assertEqual(
            r['channel_data']['voice']['speech_url'], 'http://test.mp3')
        self.assertEqual(r['channel_data']['voice']['wait_for'], '#')
        self.assertEqual(
            r['event_url'], 'http://example.com/api/v1/events/junebug')

    def test_fire_metric(self):
        '''
        Using the fire_metric function should result in an exception being
        raised, since Junebug doesn't support metrics sending.
        '''
        channel = Channel.objects.get(channel_id="JUNE_VOICE")
        message_sender = MessageClientFactory.create(channel)
        self.assertRaises(
            JunebugApiSenderException, message_sender.fire_metric, 'foo.bar',
            3.0, agg='sum')


class TestConcurrencyLimiter(AuthenticatedAPITestCase):
    def make_outbound(self, to_addr, channel=None):

        if channel:
            channel = Channel.objects.get(channel_id=channel)

        self.add_identity_search_response(to_addr, '098734738')

        self._replace_post_save_hooks_outbound()  # don't let fixtures fire
        outbound_message = {
            "to_addr": to_addr,
            "vumi_message_id": "075a32da-e1e4-4424-be46-1d09b71056fd",
            "content": "Simple outbound message",
            "delivered": False,
            "metadata": {"voice_speech_url": "http://test.com"},
            "channel": channel
        }
        outbound = Outbound.objects.create(**outbound_message)
        self._restore_post_save_hooks_outbound()  # let tests fire tasks
        return outbound

    def set_cache_entry(self, msg_type, bucket, value):
        key = "%s_messages_at_%s" % (msg_type, bucket)
        self.fake_cache.cache_data[key] = value

    def setUp(self):
        super(TestConcurrencyLimiter, self).setUp()
        self.fake_cache = MockCache()

    @responses.activate
    @patch('time.time', MagicMock(return_value=1479131658.000000))
    @patch('django.core.cache.cache.get')
    @patch('django.core.cache.cache.add')
    @patch('django.core.cache.cache.incr')
    def test_limiter_limit_not_reached(self, mock_incr, mock_add, mock_get):
        """
        Messages under the limit should get sent.
        """
        # Fake cache calls
        mock_incr.side_effect = self.fake_cache.incr
        mock_add.side_effect = self.fake_cache.add
        mock_get.side_effect = self.fake_cache.get

        outbound1 = self.make_outbound(to_addr="+27123", channel="JUNE_VOICE2")
        outbound2 = self.make_outbound(to_addr="+27987", channel="JUNE_VOICE2")

        send_message(outbound1.pk)
        send_message(outbound2.pk)

        self.assertTrue(self.check_logs(
            "Message: '%s' sent to '%s' [session_event: new] [voice: "
            "{'speech_url': 'http://test.com'}]" %
            (outbound1.content, outbound1.to_addr)))
        self.assertTrue(self.check_logs(
            "Message: '%s' sent to '%s' [session_event: new] [voice: "
            "{'speech_url': 'http://test.com'}]" %
            (outbound2.content, outbound2.to_addr)))
        outbound1.refresh_from_db()
        self.assertIsNotNone(outbound1.last_sent_time)
        outbound2.refresh_from_db()
        self.assertIsNotNone(outbound2.last_sent_time)
        self.assertEqual(len(self.fake_cache.cache_data), 1)
        bucket = 1479131658 // 60  # time() // bucket_size
        self.assertEqual(
            self.fake_cache.cache_data["JUNE_VOICE2_messages_at_%s" % bucket],
            2)

    @responses.activate
    @patch('time.time', MagicMock(return_value=1479131658.000000))
    @patch('django.core.cache.cache.get')
    @patch('django.core.cache.cache.add')
    @patch('django.core.cache.cache.incr')
    @patch('message_sender.tasks.send_message.retry')
    def test_limiter_limit_reached(self, mock_retry, mock_incr, mock_add,
                                   mock_get):
        """
        Messages under the limit should get sent. Messages over the limit
        should get retried
        """
        mock_retry.side_effect = Retry

        # Fake cache calls
        mock_incr.side_effect = self.fake_cache.incr
        mock_add.side_effect = self.fake_cache.add
        mock_get.side_effect = self.fake_cache.get

        outbound1 = self.make_outbound(to_addr="+27123", channel="JUNE_VOICE")
        outbound2 = self.make_outbound(to_addr="+27987", channel="JUNE_VOICE")

        send_message(outbound1.pk)
        with self.assertRaises(Retry):
            send_message(outbound2.pk)
        mock_retry.assert_called_with(countdown=100)

        self.assertTrue(self.check_logs(
            "Message: '%s' sent to '%s' [session_event: new] [voice: "
            "{'speech_url': 'http://test.com'}]" %
            (outbound1.content, outbound1.to_addr)))
        self.assertFalse(self.check_logs(
            "Message: '%s' sent to '%s' [session_event: new] "
            "[voice: {'speech_url': 'http://test.com'}]" %
            (outbound2.content, outbound2.to_addr)))
        outbound1.refresh_from_db()
        self.assertIsNotNone(outbound1.last_sent_time)
        outbound2.refresh_from_db()
        self.assertIsNone(outbound2.last_sent_time)
        self.assertEqual(len(self.fake_cache.cache_data), 1)
        bucket = 1479131658 // 60  # time() // bucket_size
        self.assertEqual(
            self.fake_cache.cache_data["JUNE_VOICE_messages_at_%s" % bucket],
            1)

    @patch('time.time', MagicMock(return_value=1479131640.000000))
    @patch('django.core.cache.cache.get')
    def test_limiter_buckets(self, mock_get):
        """
        The correct buckets should count towards the message count.
        """

        # Fake cache calls
        mock_get.side_effect = self.fake_cache.get
        now = 1479131640

        self.set_cache_entry("JUNE_VOICE", (now - 200) // 60, 1)  # Too old
        self.set_cache_entry("JUNE_VOICE", (now - 121) // 60, 10)  # Over delay
        self.set_cache_entry("JUNE_VOICE", (now - 120) // 60, 100)  # Within delay # noqa
        self.set_cache_entry("JUNE_VOICE", now // 60, 1000)  # Now
        self.set_cache_entry("JUNE_VOICE", (now + 60) // 60, 10000)  # In future # noqa

        channel = Channel.objects.get(channel_id="JUNE_VOICE")
        count = ConcurrencyLimiter.get_current_message_count(channel)
        self.assertEqual(count, 1100)

    @patch('time.time', MagicMock(return_value=1479131658.000000))
    @patch('django.core.cache.cache.get_or_set')
    @patch('django.core.cache.cache.decr')
    def test_limiter_decr_count(self, mock_decr, mock_get_or_set):
        """
        Events for messages should decrement the counter unless the message is
        too old.
        """

        # Fake cache calls
        mock_get_or_set.side_effect = self.fake_cache.get_or_set
        mock_decr.side_effect = self.fake_cache.decr

        self.set_cache_entry("JUNE_VOICE", 1479131535 // 60, 1)  # Past delay
        self.set_cache_entry("JUNE_VOICE", 1479131588 // 60, 1)  # Within delay
        self.set_cache_entry("JUNE_VOICE", 1479131648 // 60, -0)  # Invalid value  # noqa

        channel = Channel.objects.get(channel_id="JUNE_VOICE")

        def get_utc(timestamp):
            return datetime.fromtimestamp(timestamp).replace(
                tzinfo=timezone.now().tzinfo)

        ConcurrencyLimiter.decr_message_count(channel, get_utc(1479131535))
        ConcurrencyLimiter.decr_message_count(channel, get_utc(1479131588))
        ConcurrencyLimiter.decr_message_count(channel, get_utc(1479131608))

        self.assertEqual(self.fake_cache.cache_data, {
            "JUNE_VOICE_messages_at_24652192": 1,
            "JUNE_VOICE_messages_at_24652193": 0,
            "JUNE_VOICE_messages_at_24652194": 0})

    def test_event_nack_concurrency_decr(self):
        channel = Channel.objects.get(channel_id='VUMI_VOICE')
        outbound_message = {
            "to_addr": "+27123",
            "vumi_message_id": "08b34de7-c6da-4853-a74d-9458533ed169",
            "content": "Simple outbound message",
            "channel": channel,
            "delivered": False,
            "attempts": 3,
            "metadata": {}
        }
        failed = Outbound.objects.create(**outbound_message)
        failed.last_sent_time = failed.created_at
        failed.save()
        post_save.connect(
            psh_fire_msg_action_if_new,
            sender=Outbound,
            dispatch_uid='psh_fire_msg_action_if_new'
        )
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

        with patch.object(ConcurrencyLimiter, 'decr_message_count') as \
                mock_method:
            response = self.client.post('/api/v1/events',
                                        json.dumps(nack),
                                        content_type='application/json')
            mock_method.assert_called_once_with(channel, failed.created_at)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d = Outbound.objects.get(pk=failed.id)
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 3)  # not moved on as last attempt passed
        self.assertEqual(d.metadata["nack_reason"],
                         "no answer")
        self.assertEquals(False, self.check_logs(
            "Message: 'Simple outbound message' sent to '+27123'"
            "[session_event: new]"))

    @patch('django.core.cache.cache.get_or_set')
    @patch('django.core.cache.cache.decr')
    @patch('message_sender.views.fire_delivery_hook')
    @patch("message_sender.tasks.send_message.delay")
    def test_event_nack_concurrency_decr_june(
            self, mock_send_message, mock_hook, mock_get_or_set, mock_decr):
        '''
        A rejected event should retry and update the message object accordingly
        '''
        # Fake cache calls
        mock_get_or_set.side_effect = self.fake_cache.get_or_set
        mock_decr.side_effect = self.fake_cache.decr

        channel = Channel.objects.get(channel_id="VUMI_VOICE")
        d = self.make_outbound(to_addr='+27123', channel=channel.channel_id)
        d.last_sent_time = d.created_at
        d.save()

        post_save.connect(
            psh_fire_msg_action_if_new,
            sender=Outbound,
            dispatch_uid='psh_fire_msg_action_if_new'
        )
        nack = {
            "event_type": "rejected",
            "message_id": d.vumi_message_id,
            "channel-id": "channel-uuid-1234",
            "timestamp": "2015-10-28 16:19:37.485612",
            "event_details": {"reason": "No answer"},
        }
        with patch.object(ConcurrencyLimiter, 'decr_message_count') as \
                mock_method:
            response = self.client.post(
                '/api/v1/events/junebug', json.dumps(nack),
                content_type='application/json')
            mock_method.assert_called_once_with(channel, d.created_at)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d.refresh_from_db()
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 0)
        self.assertEqual(
            d.metadata["nack_reason"], {"reason": "No answer"})
        mock_hook.assert_called_once_with(d)

    @patch('django.core.cache.cache.get_or_set')
    @patch('django.core.cache.cache.decr')
    @patch('message_sender.views.fire_delivery_hook')
    @patch("message_sender.tasks.send_message.delay")
    def test_event_delivery_failed_concurrency_decr_june(
            self, mock_send_message, mock_hook, mock_get_or_set, mock_decr):
        '''
        A failed delivery should retry and update the message accordingly.
        '''
        # Fake cache calls
        mock_get_or_set.side_effect = self.fake_cache.get_or_set
        mock_decr.side_effect = self.fake_cache.decr

        channel = Channel.objects.get(channel_id="VUMI_VOICE")
        d = self.make_outbound(to_addr='+27123', channel=channel.channel_id)
        d.last_sent_time = d.created_at
        d.save()
        dr = {
            "event_type": "delivery_failed",
            "message_id": d.vumi_message_id,
            "channel-id": "channel-uuid-1234",
            "timestamp": "2015-10-28 16:19:37.485612",
            "event_details": {},
        }
        with patch.object(ConcurrencyLimiter, 'decr_message_count') as \
                mock_method:
            response = self.client.post(
                '/api/v1/events/junebug', json.dumps(dr),
                content_type='application/json')
            mock_method.assert_called_once_with(channel, d.created_at)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        d.refresh_from_db()
        self.assertEqual(d.delivered, False)
        self.assertEqual(d.attempts, 0)
        self.assertEqual(
            d.metadata["delivery_failed_reason"], {})
        mock_hook.assert_called_once_with(d)


class TestRequeueFailedTasks(AuthenticatedAPITestCase):
    def make_outbound(self, to_addr, channel=None):

        if channel:
            channel = Channel.objects.get(channel_id=channel)

        self.add_identity_search_response(to_addr, '34857985789')

        self._replace_post_save_hooks_outbound()  # don't let fixtures fire
        outbound_message = {
            "to_addr": to_addr,
            "vumi_message_id": "075a32da-e1e4-4424-be46-1d09b71056fd",
            "content": "Simple outbound message",
            "delivered": False,
            "metadata": {"voice_speech_url": "http://test.com"},
            "channel": channel
        }
        outbound = Outbound.objects.create(**outbound_message)
        self._restore_post_save_hooks_outbound()  # let tests fire tasks
        return outbound

    @responses.activate
    def test_requeue(self):
        outbound1 = self.make_outbound(to_addr="+27123")
        outbound2 = self.make_outbound(to_addr="+27987")
        OutboundSendFailure.objects.create(
            outbound=outbound1,
            task_id=uuid.uuid4(),
            initiated_at=timezone.now(),
            reason='Error')

        requeue_failed_tasks()

        outbound1.refresh_from_db()
        self.assertIsNotNone(outbound1.last_sent_time)
        outbound2.refresh_from_db()
        self.assertIsNone(outbound2.last_sent_time)
        self.assertEqual(OutboundSendFailure.objects.all().count(), 0)


class TestFailedTaskAPI(AuthenticatedAPITestCase):

    def make_outbound(self, to_addr, channel=None):

        if channel:
            channel = Channel.objects.get(channel_id=channel)

        self.add_identity_search_response(to_addr, '34857985789')

        self._replace_post_save_hooks_outbound()  # don't let fixtures fire
        outbound_message = {
            "to_addr": to_addr,
            "vumi_message_id": "075a32da-e1e4-4424-be46-1d09b71056fd",
            "content": "Simple outbound message",
            "delivered": False,
            "metadata": {"voice_speech_url": "http://test.com"},
            "channel": channel
        }
        outbound = Outbound.objects.create(**outbound_message)
        self._restore_post_save_hooks_outbound()  # let tests fire tasks
        return outbound

    @responses.activate
    def test_failed_tasks_requeue(self):
        outbound1 = self.make_outbound(to_addr="+27123")
        OutboundSendFailure.objects.create(
            outbound=outbound1,
            task_id=uuid.uuid4(),
            initiated_at=timezone.now(),
            reason='Error')

        response = self.client.post('/api/v1/failed-tasks/',
                                    content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["requeued_failed_tasks"], True)
        self.assertEqual(OutboundSendFailure.objects.all().count(), 0)


class TestOutboundAdmin(AuthenticatedAPITestCase):
    def setUp(self):
        super(TestOutboundAdmin, self).setUp()
        self.adminclient.login(username='testsu',
                               password='dummypwd')

    @patch("message_sender.tasks.send_message.apply_async")
    def test_resend_outbound_only_selected(self, mock_send_message):
        outbound_id = self.make_outbound()
        self.make_outbound()
        data = {'action': 'resend_outbound',
                '_selected_action': [outbound_id]}

        response = self.adminclient.post(
            reverse('admin:message_sender_outbound_changelist'), data,
            follow=True)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertContains(response, "Attempting to resend 1 message.")

        mock_send_message.assert_called_once_with(kwargs={
            "message_id": outbound_id})

    @patch("message_sender.tasks.send_message.apply_async")
    def test_resend_outbound_multiple(self, mock_send_message):
        outbound_id_1 = self.make_outbound()
        outbound_id_2 = self.make_outbound()
        data = {'action': 'resend_outbound',
                '_selected_action': [outbound_id_1, outbound_id_2]}

        response = self.adminclient.post(
            reverse('admin:message_sender_outbound_changelist'), data,
            follow=True)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertContains(response, "Attempting to resend 2 messages.")

        mock_send_message.assert_any_call(kwargs={
            "message_id": outbound_id_1})
        mock_send_message.assert_any_call(kwargs={
            "message_id": outbound_id_2})


class TestChannels(AuthenticatedAPITestCase):

    def test_channel_default_post_save(self):

        new_channel = {
            'channel_id': 'NEW_DEFAULT',
            'channel_type': Channel.JUNEBUG_TYPE,
            'default': True,
            'configuration': {
                'JUNEBUG_API_URL': 'http://example.com/',
                'JUNEBUG_API_AUTH': ('username', 'password'),
                'JUNEBUG_API_FROM': '+4321'
            },
            'concurrency_limit': 0,
            'message_timeout': 0,
            'message_delay': 0
        }

        Channel.objects.create(**new_channel)

        self.assertEqual(Channel.objects.filter(default=True).count(), 1)

        channel = Channel.objects.get(channel_id="JUNE_VOICE")
        channel.default = True
        channel.save()

        self.assertEqual(Channel.objects.filter(default=True).count(), 1)


class TestUpdateIdentityCommand(AuthenticatedAPITestCase):

    def make_identity_lookup(self, msisdn='+27123', identity='56f6e9506ee3'):
        identity = {
            "msisdn": msisdn,
            "identity": identity,
        }
        return IdentityLookup.objects.create(**identity)

    def prepare_data(self):
        self.out1 = self.make_outbound()
        self.out2 = self.make_outbound(to_addr="+274321", to_identity='')
        self.in1 = self.make_inbound('1234', from_addr='+27123')
        self.in2 = self.make_inbound('1234', from_addr='+274321')
        self.make_identity_lookup()

    def check_data(self):
        # Outbound with valid msisdn
        out1 = Outbound.objects.get(id=self.out1)
        self.assertEqual(str(out1.to_addr), "")
        self.assertEqual(str(out1.to_identity), "56f6e9506ee3")

        # Outbound msisdn not found
        out2 = Outbound.objects.get(id=self.out2)
        self.assertEqual(str(out2.to_addr), "+274321")
        self.assertEqual(str(out2.to_identity), "")

        # Inbound with valid msisdn
        in1 = Inbound.objects.get(id=self.in1)
        self.assertEqual(str(in1.from_addr), "")
        self.assertEqual(str(in1.from_identity), "56f6e9506ee3")

        # Inbound msisdn not found
        in2 = Inbound.objects.get(id=self.in2)
        self.assertEqual(str(in2.from_addr), "+274321")
        self.assertEqual(str(in2.from_identity), "")

    def test_update_identity_no_argument(self):
        self.prepare_data()
        call_command('update_identity_field')
        self.check_data()

    def test_update_identity_by_id(self):
        self.prepare_data()
        call_command('update_identity_field', '--loop', 'ID')
        self.check_data()

    def test_update_identity_by_msg(self):
        self.prepare_data()
        call_command('update_identity_field', '--loop', 'MSG')
        self.check_data()

    def test_update_identity_by_sql(self):
        self.prepare_data()
        call_command('update_identity_field', '--loop', 'SQL')
        self.check_data()
