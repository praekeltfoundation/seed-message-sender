from django.contrib import admin
from django import forms
from django.core.exceptions import ValidationError

from .models import Outbound, Inbound, Channel
from .tasks import send_message


class OutboundAdmin(admin.ModelAdmin):
    list_display = ('to_addr', 'to_identity', 'delivered', 'attempts',
                    'vumi_message_id', 'created_at', 'updated_at', 'content', )
    list_display_links = ('to_addr', 'to_identity')
    list_filter = ('delivered', 'attempts', 'created_at', 'updated_at', )
    search_fields = ['to_addr', 'to_identity']
    actions = ["resend_outbound"]

    def resend_outbound(self, request, queryset):
        resent = 0
        for record in queryset.iterator():
            send_message.apply_async(kwargs={"message_id": str(record.id)})
            resent += 1
        if resent == 1:
            output_text = "message"
        else:
            output_text = "messages"
        self.message_user(request, "Attempting to resend %s %s." % (
                          resent, output_text))

    resend_outbound.short_description = (
        "Resend selected outbounds")


class InboundAdmin(admin.ModelAdmin):
    list_display = ('message_id', 'in_reply_to', 'to_addr', 'from_addr',
                    'from_identity', 'created_at', 'updated_at', 'content', )
    list_filter = ('in_reply_to', 'from_addr', 'created_at', 'updated_at', )
    search_fields = ['to_addr', 'from_identity']


class ChannelAdminForm(forms.ModelForm):
    def clean(self):
        channel_id = self.cleaned_data['channel_id']
        channel_type = self.cleaned_data['channel_type']
        config = self.cleaned_data['configuration']

        missing = []
        if channel_type == Channel.JUNEBUG_TYPE:
            keys = ('JUNEBUG_API_URL', 'JUNEBUG_API_AUTH', 'JUNEBUG_API_FROM')

        elif channel_type == Channel.VUMI_TYPE:
            keys = ('VUMI_CONVERSATION_KEY', 'VUMI_ACCOUNT_KEY',
                    'VUMI_ACCOUNT_TOKEN', 'VUMI_API_URL')

        for key in keys:
            if key not in config.keys():
                missing.append(key)

        if missing:
            raise ValidationError(
                "Configuration keys missing: {}".format(', '.join(missing)))

        if not self.cleaned_data['default']:
            if not Channel.objects.filter(default=True).exclude(
                    channel_id=channel_id).exists():
                raise ValidationError(
                    "Please make sure there is a default channel.")

        return self.cleaned_data


class ChannelAdmin(admin.ModelAdmin):
    list_display = ('channel_id', 'channel_type', 'concurrency_limit',
                    'default')
    list_filter = ('channel_type', 'default')
    search_fields = ['channel_id']
    form = ChannelAdminForm

admin.site.register(Outbound, OutboundAdmin)
admin.site.register(Inbound, InboundAdmin)
admin.site.register(Channel, ChannelAdmin)
