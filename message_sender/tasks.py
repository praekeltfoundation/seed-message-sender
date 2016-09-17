import json
import requests

from celery.task import Task
from celery.utils.log import get_task_logger
from celery.exceptions import SoftTimeLimitExceeded

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from go_http.send import HttpApiSender
from go_http.metrics import MetricsApiClient
from requests.exceptions import HTTPError


from .models import Outbound
from seed_message_sender.utils import load_callable

logger = get_task_logger(__name__)

voice_to_addr_formatter = load_callable(settings.VOICE_TO_ADDR_FORMATTER)
text_to_addr_formatter = load_callable(settings.TEXT_TO_ADDR_FORMATTER)


class DeliverHook(Task):
    def run(self, target, payload, instance_id=None, hook_id=None, **kwargs):
        """
        target:     the url to receive the payload.
        payload:    a python primitive data structure
        instance_id:   a possibly None "trigger" instance ID
        hook_id:       the ID of defining Hook object
        """
        requests.post(
            url=target,
            data=json.dumps(payload),
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Token %s' % settings.HOOK_AUTH_TOKEN
            }
        )


def deliver_hook_wrapper(target, payload, instance, hook):
    if instance is not None:
        instance_id = instance.id
    else:
        instance_id = None
    kwargs = dict(target=target, payload=payload,
                  instance_id=instance_id, hook_id=hook.id)
    DeliverHook.apply_async(kwargs=kwargs)


def get_metric_client(session=None):
    return MetricsApiClient(
        auth_token=settings.METRICS_AUTH_TOKEN,
        api_url=settings.METRICS_URL,
        session=session)


class FireMetric(Task):

    """ Fires a metric using the MetricsApiClient
    """
    name = "seed_identity_store.identities.tasks.fire_metric"

    def run(self, metric_name, metric_value, session=None, **kwargs):
        metric_value = float(metric_value)
        metric = {
            metric_name: metric_value
        }
        metric_client = get_metric_client(session=session)
        metric_client.fire(metric)
        return "Fired metric <%s> with value <%s>" % (
            metric_name, metric_value)

fire_metric = FireMetric()


class Send_Message(Task):

    """
    Task to load and contruct message and send them off
    """
    name = "messages.tasks.send_message"

    class FailedEventRequest(Exception):

        """
        The attempted task failed because of a non-200 HTTP return
        code.
        """

    def vumi_client_text(self):
        return HttpApiSender(
            api_url=settings.VUMI_API_URL_TEXT,
            account_key=settings.VUMI_ACCOUNT_KEY_TEXT,
            conversation_key=settings.VUMI_CONVERSATION_KEY_TEXT,
            conversation_token=settings.VUMI_ACCOUNT_TOKEN_TEXT
        )

    def vumi_client_voice(self):
        return HttpApiSender(
            api_url=settings.VUMI_API_URL_VOICE,
            account_key=settings.VUMI_ACCOUNT_KEY_VOICE,
            conversation_key=settings.VUMI_CONVERSATION_KEY_VOICE,
            conversation_token=settings.VUMI_ACCOUNT_TOKEN_VOICE
        )

    def run(self, message_id, **kwargs):
        """
        Load and contruct message and send them off
        """
        l = self.get_logger(**kwargs)

        l.info("Loading Outbound Message <%s>" % message_id)
        try:
            message = Outbound.objects.get(id=message_id)
            if message.attempts < settings.MESSAGE_SENDER_MAX_RETRIES:
                l.info("Attempts: %s" % message.attempts)
                # send or resend
                try:
                    if "voice_speech_url" in message.metadata:
                        # Voice message
                        sender = self.vumi_client_voice()
                        speech_url = message.metadata["voice_speech_url"]
                        vumiresponse = sender.send_voice(
                            voice_to_addr_formatter(message.to_addr),
                            message.content,
                            speech_url=speech_url,
                            session_event="new")
                        l.info("Sent voice message to <%s>" % message.to_addr)
                    else:
                        # Plain content
                        sender = self.vumi_client_text()
                        vumiresponse = sender.send_text(
                            text_to_addr_formatter(message.to_addr),
                            message.content,
                            session_event="new")
                        l.info("Sent text message to <%s>" % message.to_addr)
                    message.attempts += 1
                    message.vumi_message_id = vumiresponse["message_id"]
                    message.save()
                    fire_metric.apply_async(kwargs={
                        "metric_name": 'vumimessage.tries.sum',
                        "metric_value": 1.0
                    })
                except HTTPError as e:
                    # retry message sending if in 500 range (3 default
                    # retries)
                    if 500 < e.response.status_code < 599:
                        raise self.retry(exc=e)
                    else:
                        raise e
                return vumiresponse
            else:
                l.info("Message <%s> at max retries." % str(message_id))
                fire_metric.apply_async(kwargs={
                    "metric_name": 'vumimessage.maxretries.sum',
                    "metric_value": 1.0
                })
        except ObjectDoesNotExist:
            logger.error('Missing Outbound message', exc_info=True)

        except SoftTimeLimitExceeded:
            logger.error(
                'Soft time limit exceed processing message send search \
                 via Celery.',
                exc_info=True)

send_message = Send_Message()
