from django import template

import seed_message_sender

register = template.Library()


@register.simple_tag
def current_version():
    return seed_message_sender.__version__
