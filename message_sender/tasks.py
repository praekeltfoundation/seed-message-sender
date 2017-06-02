import json
import random
import requests
import time

from celery.exceptions import MaxRetriesExceededError
from celery.task import Task
from celery.utils.log import get_task_logger

from datetime import datetime
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist

from go_http.metrics import MetricsApiClient
from requests import exceptions as requests_exceptions

from .factory import MessageClientFactory


from .models import Outbound, OutboundSendFailure, Channel
from seed_message_sender.utils import (
    load_callable, get_identity_address, get_identity_by_address,
    create_identity)
from seed_papertrail.decorators import papertrail

logger = get_task_logger(__name__)

voice_to_addr_formatter = load_callable(settings.VOICE_TO_ADDR_FORMATTER)
text_to_addr_formatter = load_callable(settings.TEXT_TO_ADDR_FORMATTER)


def calculate_retry_delay(attempt, max_delay=300):
    """Calculates an exponential backoff for retry attempts with a small
    amount of jitter."""
    delay = int(random.uniform(2, 4) ** attempt)
    if delay > max_delay:
        # After reaching the max delay, stop using expontential growth
        # and keep the delay nearby the max.
        delay = int(random.uniform(max_delay - 20, max_delay + 20))
    return delay


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
    def get_key(cls, channel_id, bucket):
        return "%s_messages_at_%s" % (channel_id, bucket)

    @classmethod
    def get_current_message_count(cls, channel):
        # Sum the values in all the buckets to get the total
        total = 0
        number_of_buckets = channel.message_timeout // cls.BUCKET_SIZE + 1
        bucket = int(time.time() // cls.BUCKET_SIZE)
        for i in range(bucket, bucket - number_of_buckets, -1):
            value = cache.get(cls.get_key(channel.channel_id, i))
            if value:
                total += int(value)
        return total

    @classmethod
    def incr_message_count(cls, channel_id, timeout):
        bucket = int(time.time() // cls.BUCKET_SIZE)
        key = cls.get_key(channel_id, bucket)

        # Add the bucket size to the expiry time so messages that start at
        # the end of the bucket still complete
        if not cache.add(key, 1, timeout + cls.BUCKET_SIZE):
            cache.incr(key)

    @classmethod
    def decr_message_count(cls, channel, msg_time):

        if channel.concurrency_limit == 0:
            return
        timeout = channel.message_timeout

        if not msg_time:
            return

        # Convert from datetime to seconds since epoch
        msg_time = msg_time.replace(tzinfo=None) - msg_time.utcoffset()
        msg_time = (msg_time - datetime(1970, 1, 1)).total_seconds()

        time_since = time.time() - msg_time
        if time_since > timeout:
            return
        bucket = int(msg_time // cls.BUCKET_SIZE)

        key = cls.get_key(channel.channel_id, bucket)
        # Set the expiry time to the timeout minus the time passed since
        # the message was sent.
        if int(cache.get_or_set(key, lambda: 0, timeout - time_since)) > 0:
            cache.decr(key)

    @classmethod
    def manage_limit(cls, task, channel):
        limit = channel.concurrency_limit
        timeout = channel.message_timeout
        delay = channel.message_delay

        if limit > 0:
            if cls.get_current_message_count(channel) >= limit:
                task.retry(countdown=delay)
            cls.incr_message_count(channel.channel_id, timeout)


class SendMessage(Task):

    """
    Task to load and contruct message and send them off
    """
    name = "message_sender.tasks.send_message"
    default_retry_delay = 5
    max_retries = None
    max_error_retries = 5

    class FailedEventRequest(Exception):

        """
        The attempted task failed because of a non-200 HTTP return
        code.
        """

    def get_client(self, channel=None):
        return MessageClientFactory.create(channel)

    @papertrail.debug(name, sample=0.1)
    def run(self, message_id, **kwargs):
        """
        Load and contruct message and send them off
        """
        l = self.get_logger(**kwargs)

        error_retry_count = kwargs.get('error_retry_count', 0)
        if error_retry_count >= self.max_error_retries:
            raise MaxRetriesExceededError(
                "Can't retry {0}[{1}] args:{2} kwargs:{3}".format(
                    self.name, self.request.id, self.request.args, kwargs))

        l.info("Loading Outbound Message <%s>" % message_id)
        try:
            message = Outbound.objects.select_related('channel').get(
                id=message_id)
        except ObjectDoesNotExist:
            logger.error('Missing Outbound message', exc_info=True)
            return

        if message.attempts < settings.MESSAGE_SENDER_MAX_RETRIES:
            if error_retry_count > 0:
                retry_delay = calculate_retry_delay(error_retry_count)
            else:
                retry_delay = self.default_retry_delay
            l.info("Attempts: %s" % message.attempts)
            # send or resend
            try:
                if not message.channel:
                    channel = Channel.objects.get(default=True)
                else:
                    channel = message.channel

                sender = self.get_client(channel)
                ConcurrencyLimiter.manage_limit(self, channel)

                if not message.to_addr and message.to_identity:
                    message.to_addr = get_identity_address(
                        message.to_identity, use_communicate_through=True)

                if message.to_addr and not message.to_identity:
                    result = get_identity_by_address(message.to_addr)

                    if result:
                        message.to_identity = result['results'][0]['id']
                    else:
                        identity = {
                            'details': {
                                'default_addr_type': 'msisdn',
                                'addresses': {
                                    'msisdn': {
                                        message.to_addr: {'default': True}
                                    }
                                }
                            }
                        }
                        identity = create_identity(identity)
                        message.to_identity = identity['id']

                if "voice_speech_url" in message.metadata:
                    # OBD number of tries metric
                    fire_metric.apply_async(kwargs={
                        "metric_name": 'vumimessage.obd.tries.sum',
                        "metric_value": 1.0
                    })

                    # Voice message
                    speech_url = message.metadata["voice_speech_url"]
                    vumiresponse = sender.send_voice(
                        voice_to_addr_formatter(message.to_addr),
                        message.content,
                        speech_url=speech_url,
                        session_event="new")
                    l.info("Sent voice message to <%s>" % message.to_addr)
                else:
                    # Plain content
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
            except requests_exceptions.ConnectionError as exc:
                l.info('Connection Error sending message')
                fire_metric.delay(
                    'sender.send_message.connection_error.sum', 1)
                kwargs['error_retry_count'] = error_retry_count + 1
                self.retry(exc=exc, countdown=retry_delay, args=(message_id,),
                           kwargs=kwargs)
            except requests_exceptions.Timeout as exc:
                l.info('Sending message failed due to timeout')
                fire_metric.delay('sender.send_message.timeout.sum', 1)
                kwargs['error_retry_count'] = error_retry_count + 1
                self.retry(exc=exc, countdown=retry_delay, args=(message_id,),
                           kwargs=kwargs)
            except requests_exceptions.HTTPError as exc:
                # retry message sending if in 500 range (3 default
                # retries)
                l.info('Sending message failed due to status: %s' %
                       exc.response.status_code)
                metric_name = ('sender.send_message.http_error.%s.sum' %
                               exc.response.status_code)
                fire_metric.delay(metric_name, 1)
                kwargs['error_retry_count'] = error_retry_count + 1
                self.retry(exc=exc, countdown=retry_delay, args=(message_id,),
                           kwargs=kwargs)

            # If we've gotten this far the message send was successful.
            fire_metric.apply_async(kwargs={
                "metric_name": 'message.sent.sum',
                "metric_value": 1.0
            })
            return vumiresponse

        else:
            # This is for retries based on async nacks from the transport.
            l.info("Message <%s> at max retries." % str(message_id))
            message.to_addr = ''
            message.save(update_fields=['to_addr'])
            fire_metric.apply_async(kwargs={
                "metric_name": 'vumimessage.maxretries.sum',
                "metric_value": 1.0
            })
            # Count failures on exhausted tries.
            fire_metric.apply_async(kwargs={
                "metric_name": 'message.failures.sum',
                "metric_value": 1.0
            })

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        error_retry_count = kwargs.get('error_retry_count', 0)
        if error_retry_count == self.max_error_retries:
            if 'message_id' in kwargs:
                message_id = kwargs['message_id']
            else:
                message_id = args[0]
            OutboundSendFailure.objects.create(
                outbound_id=message_id,
                initiated_at=self.request.eta,
                reason=einfo.exception.message,
                task_id=task_id
            )
            # Count permanent failures.
            fire_metric.apply_async(kwargs={
                "metric_name": 'message.failures.sum',
                "metric_value": 1.0
            })
        super(SendMessage, self).on_failure(exc, task_id, args,
                                            kwargs, einfo)


send_message = SendMessage()


class RequeueFailedTasks(Task):

    """
    Task to requeue failed Outbounds.
    """
    name = "message_sender.tasks.requeue_failed_tasks"

    def run(self, **kwargs):
        l = self.get_logger(**kwargs)
        failures = OutboundSendFailure.objects
        l.info("Attempting to requeue <%s> failed Outbound sends" %
               failures.all().count())
        for failure in failures.iterator():
            outbound_id = str(failure.outbound_id)
            # Cleanup the failure before requeueing it.
            failure.delete()
            send_message.delay(outbound_id)


requeue_failed_tasks = RequeueFailedTasks()
