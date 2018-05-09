from .models import Inbound, Outbound, OutboundSendFailure, Channel
from rest_hooks.models import Hook
from rest_framework import serializers


class OneFieldRequiredValidator:
    def __init__(self, fields):
        self.fields = fields

    def set_context(self, serializer):
        self.is_create = getattr(serializer, 'instance', None) is None

    def __call__(self, data):
        if self.is_create:

            for field in self.fields:
                if data.get(field):
                    return

            raise serializers.ValidationError(
                "One of these fields must be populated: %s" %
                (', '.join(self.fields)))


class OutboundSerializer(serializers.HyperlinkedModelSerializer):

    channel = serializers.PrimaryKeyRelatedField(
        queryset=Channel.objects.all(), required=False)

    class Meta:
        model = Outbound
        fields = (
            'url', 'id', 'version', 'to_addr', 'vumi_message_id', 'content',
            'delivered', 'attempts', 'metadata', 'created_at', 'updated_at',
            'channel', 'to_identity', 'resend')
        validators = [OneFieldRequiredValidator(['to_addr', 'to_identity'])]


class OutboundArchiveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Outbound
        fields = (
            'id', 'to_addr', 'to_identity', 'version', 'content',
            'vumi_message_id', 'delivered', 'resend', 'call_answered',
            'attempts', 'metadata', 'channel', 'updated_at', 'created_at',
            'last_sent_time', 'created_by', 'updated_by',
        )


class InboundSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = Inbound
        fields = (
            'url', 'id', 'message_id', 'in_reply_to', 'to_addr',
            'from_addr', 'content', 'transport_name', 'transport_type',
            'helper_metadata', 'created_at', 'updated_at', 'from_identity')
        validators = \
            [OneFieldRequiredValidator(['from_addr', 'from_identity'])]

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
            'updated_at', 'from_identity')
        validators = \
            [OneFieldRequiredValidator(['from', 'from_identity'])]


class WassupHookSerializer(serializers.Serializer):
    event = serializers.CharField()


class WassupDataSerializer(serializers.Serializer):
    uuid = serializers.CharField()
    from_addr = serializers.CharField()
    from_identity = serializers.CharField()
    to_addr = serializers.CharField()
    in_reply_to = serializers.CharField(allow_null=True)
    content = serializers.CharField()
    metadata = serializers.JSONField()

    class Meta:
        fields = (
            'uuid', 'from_addr', 'from_identity',
            'to_addr', 'in_reply_to', 'content', 'metadata')
        validators = \
            [OneFieldRequiredValidator(['from_addr', 'from_identity'])]


class WassupInboundSerializer(serializers.Serializer):
    """
    Maps fields from Junebug onto fields expected by the Inbound model.
    """
    hook = WassupHookSerializer()
    data = WassupDataSerializer()

    class Meta:
        fields = ('hook', 'data')

    def create(self, validated_data):
        data = validated_data['data']
        Inbound.objects.create(
            message_id=data['uuid'],
            in_reply_to=data['in_reply_to'],
            to_addr=data['to_addr'],
            from_addr=data['from_addr'],
            from_identity=data['from_identity'],
            content=data['content'],
            helper_metadata=data['metadata'])
        return validated_data


class HookSerializer(serializers.ModelSerializer):

    class Meta:
        model = Hook
        read_only_fields = ('user',)


class CreateUserSerializer(serializers.Serializer):
    email = serializers.EmailField()


class OutboundSendFailureSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = OutboundSendFailure
        fields = ('url', 'id', 'outbound', 'task_id', 'initiated_at', 'reason')


class AggregateOutboundSerializer(serializers.Serializer):
    start = serializers.DateField(required=False)
    end = serializers.DateField(required=False)


class ArchivedOutboundSerializer(serializers.Serializer):
    start = serializers.DateField()
    end = serializers.DateField()
