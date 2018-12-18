from .models import Channel


def psh_fire_msg_action_if_new(sender, instance, created, **kwargs):
    """ Post save hook to fire message send task
    """
    if created:
        from message_sender.tasks import send_message

        send_message.apply_async(kwargs={"message_id": str(instance.id)})


def update_default_channels(sender, instance, created, **kwargs):
    """ Post save hook to ensure that there is only one default
    """
    if instance.default:
        Channel.objects.filter(default=True).exclude(
            channel_id=instance.channel_id
        ).update(default=False)
