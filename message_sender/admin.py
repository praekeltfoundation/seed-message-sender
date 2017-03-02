from django.contrib import admin

from .models import Outbound, Inbound
from .tasks import send_message


class OutboundAdmin(admin.ModelAdmin):
    list_display = ('to_addr', 'delivered', 'attempts', 'vumi_message_id',
                    'created_at', 'updated_at', 'content', )
    list_filter = ('delivered', 'attempts', 'created_at', 'updated_at', )
    search_fields = ['to_addr']
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
                    'created_at', 'updated_at', 'content', )
    list_filter = ('in_reply_to', 'from_addr', 'created_at', 'updated_at', )
    search_fields = ['to_addr']


admin.site.register(Outbound, OutboundAdmin)
admin.site.register(Inbound, InboundAdmin)
