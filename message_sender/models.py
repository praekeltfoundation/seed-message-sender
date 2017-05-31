import uuid

from django.contrib.postgres.fields import JSONField
from django.contrib.auth.models import User
from django.db import models
from django.utils.encoding import python_2_unicode_compatible


@python_2_unicode_compatible
class Channel(models.Model):

    VUMI_TYPE = 'vumi'
    JUNEBUG_TYPE = 'junebug'

    CHANNEL_TYPES = (
        (JUNEBUG_TYPE, 'Junebug'),
        (VUMI_TYPE, 'Vumi')
    )

    channel_id = models.CharField(primary_key=True, editable=True,
                                  max_length=64)
    channel_type = models.CharField(choices=CHANNEL_TYPES, max_length=20,
                                    default=JUNEBUG_TYPE)
    concurrency_limit = models.IntegerField(null=False, blank=False, default=0)
    message_delay = models.IntegerField(null=False, blank=False, default=0)
    message_timeout = models.IntegerField(null=False, blank=False, default=0)
    default = models.BooleanField(default=False)
    configuration = JSONField()

    def __str__(self):  # __unicode__ on Python 2
        return str(self.channel_id)


class InvalidMessage(Exception):
    """
    The message that has been stored in the database is not a valid message.
    """
    def __init__(self, message):
        return super(InvalidMessage, self).__init__(
            'Invalid message: {}'.format(message.id))


@python_2_unicode_compatible
class Outbound(models.Model):

    """
    Contacts outbound messages and their status.
    Delivered is set to true when ack received because delivery reports patchy
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    to_addr = models.CharField(null=False, blank=True, max_length=500,
                               db_index=True)
    to_identity = models.CharField(max_length=36, null=False, blank=True,
                                   db_index=True)
    version = models.IntegerField(default=1)
    content = models.CharField(null=True, blank=True, max_length=1000)
    vumi_message_id = models.CharField(null=True, blank=True, max_length=36,
                                       db_index=True)
    delivered = models.BooleanField(default=False)
    call_answered = models.NullBooleanField(
        default=None, null=True, blank=True, help_text="True if the call has "
        "been answered. Not used for text messages")
    attempts = models.IntegerField(default=0)
    metadata = JSONField()
    channel = models.ForeignKey(Channel, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_sent_time = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, related_name='outbounds_created',
                                   null=True)
    updated_by = models.ForeignKey(User, related_name='outbounds_updated',
                                   null=True)
    user = property(lambda self: self.created_by)

    def __str__(self):  # __unicode__ on Python 2
        return str(self.id)


@python_2_unicode_compatible
class Inbound(models.Model):

    """
    Contacts inbound messages from Vumi
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message_id = models.CharField(null=False, blank=False, max_length=36)
    in_reply_to = models.CharField(null=True, blank=True, max_length=36)
    to_addr = models.CharField(null=False, blank=False, max_length=255)
    from_addr = models.CharField(
        null=False, blank=True, max_length=255, db_index=True)
    from_identity = models.CharField(max_length=36, null=False, blank=True,
                                     db_index=True, default="")
    content = models.CharField(null=True, blank=True, max_length=1000)
    transport_name = models.CharField(null=False, blank=False, max_length=200)
    transport_type = models.CharField(null=True, blank=True, max_length=200)
    helper_metadata = JSONField()
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    created_by = models.ForeignKey(User, related_name='inbounds_created',
                                   null=True)
    updated_by = models.ForeignKey(User, related_name='inbounds_updated',
                                   null=True)
    user = property(lambda self: self.created_by)

    def __str__(self):  # __unicode__ on Python 2
        return str(self.id)


@python_2_unicode_compatible
class OutboundSendFailure(models.Model):
    outbound = models.ForeignKey(Outbound, on_delete=models.CASCADE)
    task_id = models.UUIDField()
    initiated_at = models.DateTimeField()
    reason = models.TextField()

    def __str__(self):  # __unicode__ on Python 2
        return str(self.id)


@python_2_unicode_compatible
class IdentityLookup(models.Model):

    msisdn = models.CharField(primary_key=True, max_length=255)
    identity = models.CharField(max_length=36, null=False, blank=False)

    def __str__(self):  # __unicode__ on Python 2
        return str(self.identity)
