from django.contrib import admin

from .models import Outbound, Inbound


class OutboundAdmin(admin.ModelAdmin):
    list_display = ('to_addr', 'delivered', 'attempts', 'vumi_message_id',
                    'created_at', 'updated_at', 'content', )
    list_filter = ('to_addr', 'delivered', 'attempts', 'vumi_message_id',
                   'created_at', 'updated_at', )


class InboundAdmin(admin.ModelAdmin):
    list_display = ('message_id', 'in_reply_to', 'to_addr', 'from_addr',
                    'created_at', 'updated_at', 'content', )
    list_filter = ('message_id', 'in_reply_to', 'to_addr', 'from_addr',
                   'created_at', 'updated_at', )

admin.site.register(Outbound, OutboundAdmin)
admin.site.register(Inbound, InboundAdmin)
