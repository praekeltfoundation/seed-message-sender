import json
import requests
import time

from celery.task import Task
from celery.utils.log import get_task_logger
from celery.exceptions import SoftTimeLimitExceeded

from datetime import datetime
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist

from go_http.metrics import MetricsApiClient
from requests.exceptions import HTTPError

from .factory import MessageClientFactory


from .models import Outbound
from seed_message_sender.utils import load_callable
from seed_papertrail.decorators import papertrail

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
    name = "message_sender.tasks.fire_metric"

    @papertrail.debug(name, sample=0.1)
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


class ConcurrencyLimiter(object):
    BUCKET_SIZE = 60

    @classmethod
    def get_key(cls, msg_type, bucket):
        return "%s_messages_at_%s" % (msg_type, bucket)

    @classmethod
    def get_current_message_count(cls, msg_type, timeout):
        # Sum the values in all the buckets to get the total
        total = 0
        number_of_buckets = timeout // cls.BUCKET_SIZE + 1
        bucket = int(time.time() // cls.BUCKET_SIZE)
        for i in range(bucket, bucket - number_of_buckets, -1):
            value = cache.get(cls.get_key(msg_type, i))
            if value:
                total += int(value)
        return total

    @classmethod
    def incr_message_count(cls, msg_type, timeout):
        bucket = int(time.time() // cls.BUCKET_SIZE)
        key = cls.get_key(msg_type, bucket)

        # Add the bucket size to the expiry time so messages that start at
        # the end of the bucket still complete
        if not cache.add(key, 1, timeout + cls.BUCKET_SIZE):
            cache.incr(key)

    @classmethod
    def decr_message_count(cls, msg_type, msg_time):

        if msg_type == "voice":
            if int(getattr(settings, 'CONCURRENT_VOICE_LIMIT', 0)) == 0:
                return
            timeout = int(getattr(settings, 'VOICE_MESSAGE_TIMEOUT', 0))
        else:
            if int(getattr(settings, 'CONCURRENT_TEXT_LIMIT', 0)) == 0:
                return
            timeout = int(getattr(settings, 'TEXT_MESSAGE_TIMEOUT', 0))

        if not msg_time:
            return

        # Convert from datetime to seconds since epoch
        msg_time = (msg_time - datetime(1970, 1, 1)).total_seconds()

        time_since = time.time() - msg_time
        if time_since > timeout:
            return
        bucket = int(msg_time // cls.BUCKET_SIZE)

        key = cls.get_key(msg_type, bucket)
        # Set the expiry time to the timeout minus the time passed since
        # the message was sent.
        if int(cache.get_or_set(key, 0, timeout - time_since)) > 0:
            cache.decr(key)

    @classmethod
    def manage_limit(cls, task, msg_type, limit, timeout, delay):
        if limit > 0:
            if cls.get_current_message_count(msg_type, timeout) >= limit:
                task.retry(countdown=delay)
            cls.incr_message_count(msg_type, timeout)


class Send_Message(Task):

    """
    Task to load and contruct message and send them off
    """
    name = "message_sender.tasks.send_message"
    max_retries = None

    class FailedEventRequest(Exception):

        """
        The attempted task failed because of a non-200 HTTP return
        code.
        """

    def get_text_client(self):
        return MessageClientFactory.create('text')

    def get_voice_client(self):
        return MessageClientFactory.create('voice')

    @papertrail.debug(name, sample=0.1)
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

                        # OBD number of tries metric
                        fire_metric.apply_async(kwargs={
                            "metric_name": 'vumimessage.obd.tries.sum',
                            "metric_value": 1.0
                        })

                        # Voice message
                        ConcurrencyLimiter.manage_limit(
                            self, "voice",
                            int(getattr(settings,
                                        'CONCURRENT_VOICE_LIMIT', 0)),
                            int(getattr(settings, 'VOICE_MESSAGE_TIMEOUT', 0)),
                            int(getattr(settings, 'VOICE_MESSAGE_DELAY', 0)))
                        sender = self.get_voice_client()
                        # Start call. We send the voice message on the ack.
                        vumiresponse = sender.send_voice(
                            voice_to_addr_formatter(message.to_addr),
                            None, session_event="new")
                        message.call_answered = False
                        l.info("Sent voice message to <%s>" % message.to_addr)
                    else:
                        # Plain content
                        ConcurrencyLimiter.manage_limit(
                            self, "text",
                            int(getattr(settings, 'CONCURRENT_TEXT_LIMIT', 0)),
                            int(getattr(settings, 'TEXT_MESSAGE_TIMEOUT', 0)),
                            int(getattr(settings, 'TEXT_MESSAGE_DELAY', 0)))
                        sender = self.get_text_client()
                        vumiresponse = sender.send_text(
                            text_to_addr_formatter(message.to_addr),
                            message.content,
                            session_event="new")
                        l.info("Sent text message to <%s>" % (
                            message.to_addr,))
                    message.last_sent_time = datetime.now()
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
                        # Count permanent failures.
                        fire_metric.apply_async(kwargs={
                            "metric_name": 'message.failures.sum',
                            "metric_value": 1.0
                        })
                        raise e
                # If we've gotten this far the message send was successful.
                fire_metric.apply_async(kwargs={
                    "metric_name": 'message.sent.sum',
                    "metric_value": 1.0
                })
                return vumiresponse

            else:
                l.info("Message <%s> at max retries." % str(message_id))
                fire_metric.apply_async(kwargs={
                    "metric_name": 'vumimessage.maxretries.sum',
                    "metric_value": 1.0
                })
                # Count failures on exhausted tries.
                fire_metric.apply_async(kwargs={
                    "metric_name": 'message.failures.sum',
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
