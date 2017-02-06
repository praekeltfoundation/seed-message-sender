import uuid

from django.contrib.postgres.fields import JSONField
from django.contrib.auth.models import User
from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.db.models.signals import post_save
from django.dispatch import receiver


@python_2_unicode_compatible
class Outbound(models.Model):

    """
    Contacts outbound messages and their status.
    Delivered is set to true when ack received because delivery reports patchy
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    to_addr = models.CharField(null=False, blank=False, max_length=500)
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
    from_addr = models.CharField(null=False, blank=False, max_length=255)
    content = models.CharField(null=True, blank=True, max_length=1000)
    transport_name = models.CharField(null=False, blank=False, max_length=200)
    transport_type = models.CharField(null=True, blank=True, max_length=200)
    helper_metadata = JSONField()
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, related_name='inbounds_created',
                                   null=True)
    updated_by = models.ForeignKey(User, related_name='inbounds_updated',
                                   null=True)
    user = property(lambda self: self.created_by)

    def __str__(self):  # __unicode__ on Python 2
        return str(self.id)

# Make sure new messages are sent

from .tasks import send_message  # noqa


@receiver(post_save, sender=Outbound)
def fire_msg_action_if_new(sender, instance, created, **kwargs):
    if created:
        send_message.apply_async(kwargs={"message_id": str(instance.id)})


@receiver(post_save, sender=Inbound)
def fire_metrics_if_new(sender, instance, created, **kwargs):
    from .tasks import fire_metric
    if created:
        fire_metric.apply_async(kwargs={
            "metric_name": 'inbounds.created.sum',
            "metric_value": 1.0
        })
