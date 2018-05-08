import json
import os
import re
import pkg_resources

from copy import deepcopy
from django.conf import settings
from django.core.urlresolvers import reverse

import requests
from six.moves import urllib_parse

from go_http.send import HttpApiSender

from .utils import make_absolute_url
from .models import Channel


class FactoryException(Exception):
    pass


class HttpApiSenderException(Exception):
    pass


class GenericHttpApiSender(HttpApiSender):

    def __init__(self, url, auth=None, from_addr=None, session=None,
                 override_payload=None, strip_filepath=False):
        """
        :param url str: The URL for the HTTP API channel
        :param auth tuple: (username, password) or anything
            accepted by the requests library. Defaults to None.
        :param session requests.Session: A requests session. Defaults to None
        :param from_addr str: The from address for all messages. Defaults to
            None
        :param override_payload dict: This is the format of the payload that
            needs to be sent to the URL. It willl be populated from the
            original payload. Defaults to None
        :param strip_filepath boolean: This should be true if we only need to
            send the filename to the api.
        """
        self.api_url = url
        self.auth = tuple(auth) if isinstance(auth, list) else auth
        self.from_addr = from_addr
        if session is None:
            session = requests.Session()
        self.session = session
        self.override_payload = override_payload
        self.strip_filepath = strip_filepath

    def _get_filename(self, path):
        """
        This function gets the base filename from the path, if a language code
        is present the filename will start from there.
        """
        match = re.search('[a-z]{2,3}_[A-Z]{2}', path)

        if match:
            start = match.start(0)
            filename = path[start:]
        else:
            filename = os.path.basename(path)

        return filename

    def _raw_send(self, py_data):
        headers = {'content-type': 'application/json; charset=utf-8'}

        channel_data = py_data.get('helper_metadata', {})
        channel_data['session_event'] = py_data.get('session_event')

        url = channel_data.get('voice', {}).get('speech_url')
        if self.strip_filepath and url:
            if not isinstance(url, (list, tuple)):
                channel_data['voice']['speech_url'] = self._get_filename(url)
            else:
                channel_data['voice']['speech_url'] = []
                for item in url:
                    channel_data['voice']['speech_url'].append(
                        self._get_filename(item))

        data = {
            'to': py_data['to_addr'],
            'from': self.from_addr,
            'content': py_data['content'],
            'channel_data': channel_data
        }

        data = self._override_payload(data)

        data = json.dumps(data)
        r = self.session.post(self.api_url, auth=self.auth,
                              data=data, headers=headers,
                              timeout=settings.DEFAULT_REQUEST_TIMEOUT)
        r.raise_for_status()
        res = r.json()
        return res.get('result', {})

    def _override_payload(self, payload):
        """
        This function transforms the payload into a new format using the
        self.override_payload property.
        """
        if self.override_payload:
            old_payload = payload

            def get_value(data, key):
                try:
                    parent_key, nested_key = key.split('.', 1)
                    return get_value(data.get(parent_key, {}), nested_key)
                except ValueError:
                    return data.get(key, key)

            def set_values(data):
                for key, value in data.items():
                    if isinstance(value, dict):
                        set_values(value)
                    else:
                        data[key] = get_value(old_payload, value)

            payload = deepcopy(self.override_payload)
            set_values(payload)

        return payload

    def fire_metric(self, metric, value, agg="last"):
        raise HttpApiSenderException(
            'Metrics sending not supported')


class JunebugApiSender(GenericHttpApiSender):

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


class WassupApiSenderException(Exception):
    pass


WASSUP_SESSIONS = {}


class WassupApiSender(object):

    def __init__(self, api_url, token, hsm_uuid, number=None, session=None):
        self.api_url = api_url
        self.token = token
        self.hsm_uuid = hsm_uuid
        self.number = number

        distribution = pkg_resources.get_distribution('seed_message_sender')

        # reuse sessions on tokens to make use of SSL keep-alive
        # but keep some separation around auth
        self.session = (
            session or WASSUP_SESSIONS.setdefault(token, requests.Session()))
        self.session.headers.update({
            'Authorization': 'Token %s' % (self.token,),
            'User-Agent': 'SeedMessageSender/%s' % (
                distribution.version,)
        })

    def send_text(self, to_addr, content, session_event=None):
        response = self.session.post(
            urllib_parse.urljoin(
                self.api_url, '/api/v1/hsms/%s/send/' % (self.hsm_uuid,)),
            json={
                "to_addr": to_addr,
                "localizable_params": [{"default": content}]
            })
        response.raise_for_status()
        data = response.json()
        # the SendMessage task expects the sender to return a dict with
        # a ``message_id`` field set. I'm injecting that here manually to
        # comply
        data.update({
            "message_id": data["uuid"],
        })
        return data

    def send_voice(self, to_addr, content, speech_url=None, wait_for=None,
                   session_event=None):
        if not self.number:
            raise WassupApiSenderException(
                'Cannot send an audio file if a number is not specified.')

        audio_file = requests.get(speech_url, stream=True)
        audio_file.raise_for_status()

        response = self.session.post(
            urllib_parse.urljoin(
                self.api_url, '/api/v1/messages/'),
            files={
                'audio_attachment': audio_file.raw,
            },
            data={
                'to_addr': to_addr,
                'number': self.number,
            })
        response.raise_for_status()
        data = response.json()
        data.update({
            "message_id": data["uuid"]
        })
        return data

    def fire_metric(self, metric, value, agg="last"):
        raise WassupApiSenderException(
            'Metrics sending not supported')


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
    def create_wassup_client(cls, channel):
        return WassupApiSender(
            channel.configuration.get('WASSUP_API_URL'),
            channel.configuration.get('WASSUP_API_TOKEN'),
            channel.configuration.get('WASSUP_API_HSM_UUID'),
            number=channel.configuration.get('WASSUP_API_NUMBER'))

    @classmethod
    def create_vumi_client(cls, channel):
        return HttpApiSender(
            channel.configuration.get("VUMI_ACCOUNT_KEY"),
            channel.configuration.get("VUMI_CONVERSATION_KEY"),
            channel.configuration.get("VUMI_ACCOUNT_TOKEN"),
            api_url=channel.configuration.get("VUMI_API_URL")
        )

    @classmethod
    def create_http_api_client(cls, channel):
        return GenericHttpApiSender(
            channel.configuration.get("HTTP_API_URL"),
            channel.configuration.get("HTTP_API_AUTH"),
            channel.configuration.get("HTTP_API_FROM"),
            override_payload=channel.configuration.get("OVERRIDE_PAYLOAD"),
            strip_filepath=channel.configuration.get("STRIP_FILEPATH"),
        )
