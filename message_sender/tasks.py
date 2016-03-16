import json
import requests

from celery.task import Task
from celery.utils.log import get_task_logger
from celery.exceptions import SoftTimeLimitExceeded

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from go_http.send import HttpApiSender
from requests.exceptions import HTTPError

from .models import Outbound

logger = get_task_logger(__name__)


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


class Send_Metric(Task):

    """
    Task to fire metrics
    TODO: Replace fire with metrics client creation when ready.
    """
    name = "messages.tasks.send_metric"

    class FailedEventRequest(Exception):

        """
        The attempted task failed because of a non-200 HTTP return
        code.
        """

    def vumi_client(self):
        return HttpApiSender(
            account_key=settings.VUMI_ACCOUNT_KEY_TEXT,
            conversation_key=settings.VUMI_CONVERSATION_KEY_TEXT,
            conversation_token=settings.VUMI_ACCOUNT_TOKEN_TEXT
        )

    def run(self, metric, value, agg, **kwargs):
        """
        Returns count from api
        """
        l = self.get_logger(**kwargs)

        l.info("Firing metric: %r [%s] -> %g" % (metric, agg, float(value)))
        try:
            # TODO: Real metric firing
            # sender = self.vumi_client()
            # result = sender.fire_metric(metric, value, agg=agg)
            result = {"success": "Fake metric fired"}
            l.info("Result of firing metric: %s" % (result["success"]))
            return result

        except SoftTimeLimitExceeded:
            logger.error(
                'Soft time limit exceed processing metric fire \
                 via Celery.',
                exc_info=True)

send_metric = Send_Metric()


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

        l.info("Loading Outbound Message")
        try:
            message = Outbound.objects.get(id=message_id)
            if message.attempts < settings.MESSAGE_SENDER_MAX_RETRIES:
                print("Attempts: %s" % message.attempts)
                # send or resend
                try:
                    if "voice_speech_url" in message.metadata:
                        # Voice message
                        sender = self.vumi_client_voice()
                        speech_url = message.metadata["voice_speech_url"]
                        vumiresponse = sender.send_voice(
                            message.to_addr, message.content,
                            speech_url=speech_url,
                            session_event="new")
                        l.info("Sent voice message to <%s>" % message.to_addr)
                    else:
                        # Plain content
                        sender = self.vumi_client_text()
                        vumiresponse = sender.send_text(
                            message.to_addr, message.content,
                            session_event="new")
                        l.info("Sent text message to <%s>" % message.to_addr)
                    message.attempts += 1
                    message.vumi_message_id = vumiresponse["message_id"]
                    message.save()
                    send_metric.delay(metric="vumimessage.tries", value=1,
                                      agg="sum")
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
                send_metric.delay(metric="vumimessage.maxretries", value=1,
                                  agg="sum")
        except ObjectDoesNotExist:
            logger.error('Missing Outbound message', exc_info=True)

        except SoftTimeLimitExceeded:
            logger.error(
                'Soft time limit exceed processing message send search \
                 via Celery.',
                exc_info=True)

send_message = Send_Message()
