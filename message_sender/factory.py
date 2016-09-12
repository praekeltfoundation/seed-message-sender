import json

from django.conf import settings

import requests

from go_http.send import HttpApiSender


class MessageClientFactoryException(Exception):
    pass


class JunebugApiSenderException(Exception):
    pass


class JunebugApiSender(HttpApiSender):

    def __init__(self, url, auth=None, session=None):
        """
        :param url str: The URL for the Junebug HTTP channel
        :param auth tuple: (username, password) or anything
            accepted by the requests library. Defaults to None.
        :param session requests.Session: A requests session. Defaults to None
        """
        self.api_url = url
        self.auth = auth
        if session is None:
            session = requests.Session()
        self.session = session

    def _raw_send(self, py_data):
        headers = {'content-type': 'application/json; charset=utf-8'}
        data = json.dumps(py_data)
        r = self.session.post(self.api_url, auth=self.auth,
                              data=data, headers=headers)
        r.raise_for_status()
        return r.json()

    def fire_metric(self, metric, value, agg="last"):
        raise JunebugApiSenderException(
            'Metrics sending not supported by Junebug')


class MessageClientFactory(object):

    @classmethod
    def create(cls, client_type):
        backend_type = getattr(settings, 'MESSAGE_BACKEND', None)
        if not backend_type:
            raise MessageClientFactoryException(
                'Undefined message backend: %r' % (backend_type,))

        handler = getattr(cls,
                          'create_%s_client' % (backend_type.lower(),), None)
        if not handler:
            raise MessageClientFactoryException(
                'Unknown backend type: %r' % (backend_type,))

        return handler(client_type)

    @classmethod
    def create_junebug_client(cls, client_type):
        return JunebugApiSender(
            getattr(settings, 'JUNEBUG_API_URL_%s' % (client_type.upper(),)),
            getattr(settings, 'JUNEBUG_API_AUTH_%s' % (client_type.upper(),)))

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
