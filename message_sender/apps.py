from django.apps import AppConfig

from django.db.models.signals import post_save, pre_save  # noqa


class MessageSenderAppConfig(AppConfig):

    name = 'message_sender'

    def ready(self):
        from .signals import (psh_fire_msg_action_if_new,
                              psh_fire_metrics_if_new, update_default_channels)

        post_save.connect(
            psh_fire_msg_action_if_new,
            sender='message_sender.Outbound',
            dispatch_uid='psh_fire_msg_action_if_new')

        post_save.connect(
            psh_fire_metrics_if_new,
            sender='message_sender.Inbound',
            dispatch_uid='psh_fire_metrics_if_new')

        post_save.connect(
            update_default_channels,
            sender='message_sender.Channel',
            dispatch_uid='update_default_channels'
        )
