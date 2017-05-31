import json

from django.conf import settings
from django.core.urlresolvers import reverse

import requests

from go_http.send import HttpApiSender

from .utils import make_absolute_url
from .models import Channel


class FactoryException(Exception):
    pass


class JunebugApiSenderException(Exception):
    pass


class JunebugApiSender(HttpApiSender):

    def __init__(self, url, auth=None, from_addr=None, session=None):
        """
        :param url str: The URL for the Junebug HTTP channel
        :param auth tuple: (username, password) or anything
            accepted by the requests library. Defaults to None.
        :param session requests.Session: A requests session. Defaults to None
        :param from_addr str: The from address for all messages. Defaults to
            None
        """
        self.api_url = url
        self.auth = tuple(auth) if isinstance(auth, list) else auth
        self.from_addr = from_addr
        if session is None:
            session = requests.Session()
        self.session = session

    def _raw_send(self, py_data):
        headers = {'content-type': 'application/json; charset=utf-8'}

        channel_data = py_data.get('helper_metadata', {})
        channel_data['session_event'] = py_data.get('session_event')

        data = {
            'to': py_data['to_addr'],
            'from': self.from_addr,
            'content': py_data['content'],
            'channel_data': channel_data,
            'event_url': make_absolute_url(reverse('junebug-events')),
        }

        data = json.dumps(data)
        r = self.session.post(self.api_url, auth=self.auth,
                              data=data, headers=headers,
                              timeout=settings.DEFAULT_REQUEST_TIMEOUT)
        r.raise_for_status()
        res = r.json()
        return res.get('result', {})

    def fire_metric(self, metric, value, agg="last"):
        raise JunebugApiSenderException(
            'Metrics sending not supported by Junebug')


class MessageClientFactory(object):

    @classmethod
    def create(cls, channel=None):
        try:
            if not channel:
                channel = Channel.objects.get(default=True)
        except Channel.DoesNotExist:
            raise FactoryException(
                'Unknown backend type: %r' % (channel,))

        backend_type = channel.channel_type
        handler = getattr(cls,
                          'create_%s_client' % (backend_type,), None)
        if not handler:
            raise FactoryException(
                'Unknown backend type: %r' % (backend_type,))

        return handler(channel)

    @classmethod
    def create_junebug_client(cls, channel):
        return JunebugApiSender(
            channel.configuration.get("JUNEBUG_API_URL"),
            channel.configuration.get("JUNEBUG_API_AUTH"),
            channel.configuration.get("JUNEBUG_API_FROM")
        )

    @classmethod
    def create_vumi_client(cls, channel):
        return HttpApiSender(
            channel.configuration.get("VUMI_ACCOUNT_KEY"),
            channel.configuration.get("VUMI_CONVERSATION_KEY"),
            channel.configuration.get("VUMI_ACCOUNT_TOKEN"),
            api_url=channel.configuration.get("VUMI_API_URL")
        )
