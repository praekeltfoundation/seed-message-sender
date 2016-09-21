import json

from django.conf import settings

import requests

from go_http.send import HttpApiSender


class FactoryException(Exception):
    pass


def get_backend_type():
    backend_type = getattr(settings, 'MESSAGE_BACKEND', None)
    if not backend_type:
        raise FactoryException(
            'Undefined message backend: %r' % (backend_type,))
    return backend_type.lower()


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
        self.auth = auth
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
        }

        data = json.dumps(data)
        r = self.session.post(self.api_url, auth=self.auth,
                              data=data, headers=headers)
        r.raise_for_status()
        res = r.json()
        return {
            "message_id": res.get('result', {}).get('id')
        }

    def fire_metric(self, metric, value, agg="last"):
        raise JunebugApiSenderException(
            'Metrics sending not supported by Junebug')


class MessageClientFactory(object):

    @classmethod
    def create(cls, client_type):
        backend_type = get_backend_type()
        handler = getattr(cls,
                          'create_%s_client' % (backend_type,), None)
        if not handler:
            raise FactoryException(
                'Unknown backend type: %r' % (backend_type,))

        return handler(client_type)

    @classmethod
    def create_junebug_client(cls, client_type):
        return JunebugApiSender(
            getattr(settings, 'JUNEBUG_API_URL_%s' % (client_type.upper(),)),
            getattr(settings, 'JUNEBUG_API_AUTH_%s' % (client_type.upper(),)),
            getattr(settings, 'JUNEBUG_API_FROM_%s' % (client_type.upper())))

    @classmethod
    def create_vumi_client(cls, client_type):
        return HttpApiSender(
            getattr(settings,
                    'VUMI_ACCOUNT_KEY_%s' % (client_type.upper(),)),
            getattr(settings,
                    'VUMI_CONVERSATION_KEY_%s' % (client_type.upper(),)),
            getattr(settings,
                    'VUMI_ACCOUNT_TOKEN_%s' % (client_type.upper(),)),
            api_url=getattr(settings,
                            'VUMI_API_URL_%s' % (client_type.upper(),)),
        )


class EventListenerFactory(object):

    @classmethod
    def create(cls):
        backend_type = get_backend_type()
        if backend_type == 'vumi':
            from .views import EventListener
            return EventListener.as_view()
        elif backend_type == 'junebug':
            from .view import JunebugEventListener
            return JunebugEventListener.as_view
        raise FactoryException(
            'Unknown event handling type: %s' % (backend_type,))
