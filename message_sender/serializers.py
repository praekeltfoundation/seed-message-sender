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
        if "channel_data" in data:  # This message is from Junebug
            errors = {}
            if "reply_to" not in data:
                errors["reply_to"] = 'This field is required.'
            else:
                data['in_reply_to'] = data["reply_to"]
            if "to" not in data:
                errors['to'] = 'This field is required.'
            else:
                data['to_addr'] = data['to']
            if "from" not in data:
                errors['from'] = 'This field is required.'
            else:
                data['from_addr'] = data['from']
            if "channel_id" not in data:
                errors['channel_id'] = 'This field is required.'
            else:
                data['transport_name'] = data['channel_id']
            data['helper_metadata'] = data['channel_data']
            if errors:
                raise serializers.ValidationError(errors)

        return super(InboundSerializer, self).to_internal_value(data)


class HookSerializer(serializers.ModelSerializer):

    class Meta:
        model = Hook
        read_only_fields = ('user',)


class CreateUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
