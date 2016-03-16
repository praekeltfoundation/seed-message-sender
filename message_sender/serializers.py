from .models import Inbound, Outbound
from rest_hooks.models import Hook
from rest_framework import serializers


class OutboundSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = Outbound
        fields = (
            'url', 'id', 'version', 'to_addr', 'vumi_message_id', 'content',
            'delivered', 'attempts', 'metadata', 'created_at', 'updated_at')


class InboundSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = Inbound
        fields = (
            'url', 'id', 'message_id', 'in_reply_to', 'to_addr',
            'from_addr', 'content', 'transport_name', 'transport_type',
            'helper_metadata', 'created_at', 'updated_at')


class HookSerializer(serializers.ModelSerializer):

    class Meta:
        model = Hook
        read_only_fields = ('user',)
