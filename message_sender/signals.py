
def psh_fire_msg_action_if_new(sender, instance, created, **kwargs):
    """ Post save hook to fire message send task
    """
    if created:
        from message_sender.tasks import send_message
        send_message.apply_async(kwargs={"message_id": str(instance.id)})


def psh_fire_metrics_if_new(sender, instance, created, **kwargs):
    """ Post save hook to fire Inbound created metric
    """
    if created:
        from message_sender.tasks import fire_metric
        fire_metric.apply_async(kwargs={
            "metric_name": 'inbounds.created.sum',
            "metric_value": 1.0
        })
