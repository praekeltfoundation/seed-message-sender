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

    def to_internal_value(self, data):
        """
        Adds extra data to the helper_metadata field.
        """
        if "session_event" in data:
            data['helper_metadata']['session_event'] = data['session_event']
        return super(InboundSerializer, self).to_internal_value(data)


class JunebugInboundSerializer(serializers.HyperlinkedModelSerializer):
    """
    Maps fields from Junebug onto fields expected by the Inbound model.
    """
    reply_to = serializers.CharField(source='in_reply_to')
    to = serializers.CharField(source='to_addr')
    channel_id = serializers.CharField(source='transport_name')
    channel_data = serializers.JSONField(source='helper_metadata')

    class Meta:
        model = Inbound
        fields = (
            'url', 'id', 'message_id', 'reply_to', 'to', 'from_addr',
            'content', 'channel_id', 'channel_data', 'created_at',
            'updated_at')

    def to_internal_value(self, data):
        """
        Maps Junebug 'from' field to 'from_addr' expected by serializer since
        'from' is a python keyword.
        """
        if "from" not in data:
            raise serializers.ValidationError({
                'from': 'This field is required.'
            })
        else:
            data['from_addr'] = data['from']
        return super(JunebugInboundSerializer, self).to_internal_value(data)


class HookSerializer(serializers.ModelSerializer):

    class Meta:
        model = Hook
        read_only_fields = ('user',)


class CreateUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
