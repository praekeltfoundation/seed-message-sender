import json
import os
import re
from copy import deepcopy

import pkg_resources
import requests
from django.conf import settings
from django.urls import reverse
from go_http.send import HttpApiSender
from rest_hooks.models import Hook
from requests import exceptions as requests_exceptions
from six.moves import urllib_parse

from .models import Channel
from .utils import make_absolute_url


class FactoryException(Exception):
    pass


class HttpApiSenderException(Exception):
    pass


class VumiHttpApiSender(HttpApiSender):
    def send_image(self, to_addr, content, image_url=None):
        raise HttpApiSenderException("Sending images not available on this channel.")


class GenericHttpApiSender(VumiHttpApiSender):
    def __init__(
        self,
        url,
        auth=None,
        from_addr=None,
        session=None,
        override_payload=None,
        strip_filepath=False,
    ):
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
        match = re.search("[a-z]{2,3}_[A-Z]{2}", path)

        if match:
            start = match.start(0)
            filename = path[start:]
        else:
            filename = os.path.basename(path)

        return filename

    def _raw_send(self, py_data):
        headers = {"content-type": "application/json; charset=utf-8"}

        channel_data = py_data.get("helper_metadata", {})
        channel_data["session_event"] = py_data.get("session_event")

        url = channel_data.get("voice", {}).get("speech_url")
        if self.strip_filepath and url:
            if not isinstance(url, (list, tuple)):
                channel_data["voice"]["speech_url"] = self._get_filename(url)
            else:
                channel_data["voice"]["speech_url"] = []
                for item in url:
                    channel_data["voice"]["speech_url"].append(self._get_filename(item))

        data = {
            "to": py_data["to_addr"],
            "from": self.from_addr,
            "content": py_data["content"],
            "channel_data": channel_data,
        }

        data = self._override_payload(data)

        data = json.dumps(data)
        r = self.session.post(
            self.api_url,
            auth=self.auth,
            data=data,
            headers=headers,
            timeout=settings.DEFAULT_REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        res = r.json()
        return res.get("result", {})

    def _override_payload(self, payload):
        """
        This function transforms the payload into a new format using the
        self.override_payload property.
        """
        if self.override_payload:
            old_payload = payload

            def get_value(data, key):
                try:
                    parent_key, nested_key = key.split(".", 1)
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
        raise HttpApiSenderException("Metrics sending not supported")


class JunebugApiSender(GenericHttpApiSender):
    def _raw_send(self, py_data):
        headers = {"content-type": "application/json; charset=utf-8"}

        channel_data = py_data.get("helper_metadata", {})
        channel_data["session_event"] = py_data.get("session_event")

        data = {
            "to": py_data["to_addr"],
            "from": self.from_addr,
            "content": py_data["content"],
            "channel_data": channel_data,
            "event_url": make_absolute_url(reverse("junebug-events")),
        }

        data = json.dumps(data)
        r = self.session.post(
            self.api_url,
            auth=self.auth,
            data=data,
            headers=headers,
            timeout=settings.DEFAULT_REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        res = r.json()
        return res.get("result", {})


class WassupApiSenderException(Exception):
    pass


WASSUP_SESSIONS = {}


class WassupApiSender(object):
    def __init__(
        self, api_url, token, hsm_uuid, hsm_disabled, number=None, session=None
    ):
        self.api_url = api_url
        self.token = token
        self.hsm_uuid = hsm_uuid
        self.hsm_disabled = hsm_disabled
        self.number = number

        distribution = pkg_resources.get_distribution("seed_message_sender")

        # reuse sessions on tokens to make use of SSL keep-alive
        # but keep some separation around auth
        self.session = session or WASSUP_SESSIONS.setdefault(token, requests.Session())
        self.session.headers.update(
            {
                "Authorization": "Token %s" % (self.token,),
                "User-Agent": "SeedMessageSender/%s" % (distribution.version,),
            }
        )

    def send_text(self, to_addr, content, session_event=None):
        if self.hsm_disabled:
            if not self.number:
                raise WassupApiSenderException(
                    "Cannot send a non hsm message if a number is not " "specified."
                )

            response = self.session.post(
                urllib_parse.urljoin(self.api_url, "/api/v1/messages/"),
                json={"number": self.number, "content": content, "to_addr": to_addr},
            )
        else:
            response = self.session.post(
                urllib_parse.urljoin(
                    self.api_url, "/api/v1/hsms/%s/send/" % (self.hsm_uuid,)
                ),
                json={"to_addr": to_addr, "localizable_params": [{"default": content}]},
            )

        response.raise_for_status()
        data = response.json()
        # the SendMessage task expects the sender to return a dict with
        # a ``message_id`` field set. I'm injecting that here manually to
        # comply
        data.update({"message_id": data["uuid"]})
        return data

    def send_image(self, to_addr, content, image_url=None):
        if not self.number:
            raise WassupApiSenderException(
                "Cannot send a image file if a number is not specified."
            )

        image_file = requests.get(image_url, stream=True)
        image_file.raise_for_status()

        content_type = image_file.headers["content-type"]
        image_stream = image_file.raw
        image_name = image_url.split("/")[-1]

        response = self.session.post(
            urllib_parse.urljoin(self.api_url, "/api/v1/messages/"),
            files={"image_attachment": (image_name, image_stream, content_type, {})},
            data={
                "to_addr": to_addr,
                "number": self.number,
                "image_attachment_caption": content,
            },
        )
        response.raise_for_status()
        data = response.json()
        data.update({"message_id": data["uuid"]})
        return data

    def send_voice(
        self, to_addr, content, speech_url=None, wait_for=None, session_event=None
    ):
        if not self.number:
            raise WassupApiSenderException(
                "Cannot send an audio file if a number is not specified."
            )

        audio_file = requests.get(speech_url, stream=True)
        audio_file.raise_for_status()

        response = self.session.post(
            urllib_parse.urljoin(self.api_url, "/api/v1/messages/"),
            files={"audio_attachment": audio_file.raw},
            data={"to_addr": to_addr, "number": self.number},
        )
        response.raise_for_status()
        data = response.json()
        data.update({"message_id": data["uuid"]})
        return data

    def fire_metric(self, metric, value, agg="last"):
        raise WassupApiSenderException("Metrics sending not supported")


class WhatsAppApiSenderException(Exception):
    pass


WHATSAPP_SESSIONS = {}


class WhatsAppApiSender(object):
    def __init__(
        self, api_url, token, hsm_namespace, hsm_element_name, ttl, session=None
    ):
        self.api_url = api_url
        self.token = token
        self.hsm_namespace = hsm_namespace
        self.hsm_element_name = hsm_element_name
        self.ttl = ttl

        distribution = pkg_resources.get_distribution("seed_message_sender")

        # reuse sessions on tokens to make use of SSL keep-alive
        # but keep some separation around auth
        self.session = session or WHATSAPP_SESSIONS.setdefault(
            token, requests.Session()
        )
        self.session.headers.update(
            {
                "Authorization": "Bearer %s" % (self.token,),
                "User-Agent": "SeedMessageSender/%s" % (distribution.version,),
            }
        )

    def fire_failed_contact_lookup(self, msisdn):
        """
        Fires a webhook in the event of a failed WhatsApp contact lookup.
        """
        payload = {"address": msisdn}
        # We cannot user the raw_hook_event here, because we don't have a user, so we
        # manually filter and send the hooks for all users
        hooks = Hook.objects.filter(event="whatsapp.failed_contact_check")
        for hook in hooks:
            hook.deliver_hook(
                None, payload_override={"hook": hook.dict(), "data": payload}
            )

    def get_contact(self, msisdn):
        """
        Returns the WhatsApp ID for the given MSISDN
        """
        response = self.session.post(
            urllib_parse.urljoin(self.api_url, "/v1/contacts"),
            json={"blocking": "wait", "contacts": [msisdn]},
        )
        response.raise_for_status()
        whatsapp_id = response.json()["contacts"][0].get("wa_id")
        if not whatsapp_id:
            self.fire_failed_contact_lookup(msisdn)
        return whatsapp_id

    def send_hsm(self, whatsapp_id, content):
        data = {
            "to": whatsapp_id,
            "type": "hsm",
            "hsm": {
                "namespace": self.hsm_namespace,
                "element_name": self.hsm_element_name,
                "localizable_params": [{"default": content}],
            },
        }

        if self.ttl is not None:
            data["ttl"] = self.ttl
        response = self.session.post(
            urllib_parse.urljoin(self.api_url, "/v1/messages"), json=data
        )
        return self.return_response(response)

    def send_text_message(self, whatsapp_id, content):
        response = self.session.post(
            urllib_parse.urljoin(self.api_url, "/v1/messages"),
            json={"to": whatsapp_id, "text": {"body": content}},
        )
        return self.return_response(response)

    def return_response(self, response):
        try:
            response.raise_for_status()
        except requests_exceptions.HTTPError as exc:
            resp = exc.response.text

            if not ("1006" in resp and "unknown contact" in resp):
                raise exc

        return response.json()

    def send_text(self, to_addr, content, session_event=None):
        whatsapp_id = to_addr.replace("+", "")

        def send_message():
            if self.hsm_namespace and self.hsm_element_name:
                d = self.send_hsm(whatsapp_id, content)
            else:
                d = self.send_text_message(whatsapp_id, content)
            return d

        data = send_message()

        if (
            "errors" in data
            and data["errors"][0]["code"] == 1006
            and data["errors"][0]["details"] == "unknown contact"
        ):
            whatsapp_id = self.get_contact(to_addr)
            if not whatsapp_id:
                return {"message_id": None}

            data = send_message()

        return {"message_id": data["messages"][0]["id"]}

    def send_image(self, to_addr, content, image_url=None):
        raise WhatsAppApiSenderException("Image sending not supported")

    def send_voice(
        self, to_addr, content, speech_url=None, wait_for=None, session_event=None
    ):
        raise WhatsAppApiSenderException("Voice sending not supported")

    def fire_metric(self, metric, value, agg="last"):
        raise WhatsAppApiSenderException("Metrics sending not supported")


class MessageClientFactory(object):
    @classmethod
    def create(cls, channel=None):
        try:
            if not channel:
                channel = Channel.objects.get(default=True)
        except Channel.DoesNotExist:
            raise FactoryException("Unknown backend type: %r" % (channel,))

        backend_type = channel.channel_type
        handler = getattr(cls, "create_%s_client" % (backend_type,), None)
        if not handler:
            raise FactoryException("Unknown backend type: %r" % (backend_type,))

        return handler(channel)

    @classmethod
    def create_junebug_client(cls, channel):
        return JunebugApiSender(
            channel.configuration.get("JUNEBUG_API_URL"),
            channel.configuration.get("JUNEBUG_API_AUTH"),
            channel.configuration.get("JUNEBUG_API_FROM"),
        )

    @classmethod
    def create_wassup_client(cls, channel):
        return WassupApiSender(
            channel.configuration.get("WASSUP_API_URL"),
            channel.configuration.get("WASSUP_API_TOKEN"),
            channel.configuration.get("WASSUP_API_HSM_UUID"),
            channel.configuration.get("WASSUP_API_HSM_DISABLED", False),
            number=channel.configuration.get("WASSUP_API_NUMBER"),
        )

    @classmethod
    def create_vumi_client(cls, channel):
        return VumiHttpApiSender(
            channel.configuration.get("VUMI_ACCOUNT_KEY"),
            channel.configuration.get("VUMI_CONVERSATION_KEY"),
            channel.configuration.get("VUMI_ACCOUNT_TOKEN"),
            api_url=channel.configuration.get("VUMI_API_URL"),
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

    @classmethod
    def create_whatsapp_client(cls, channel):
        return WhatsAppApiSender(
            channel.configuration["API_URL"],
            channel.configuration["API_TOKEN"],
            channel.configuration.get("HSM_NAMESPACE"),
            channel.configuration.get("HSM_ELEMENT_NAME"),
            channel.configuration.get("TTL"),
        )
